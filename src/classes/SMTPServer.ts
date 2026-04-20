import fs from 'fs';
import path from 'path';
import { SMTPServer as NodeSMTP, SMTPServerOptions } from 'smtp-server';
import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';
import MailComposer from 'nodemailer/lib/mail-composer';
import addressparser, { Address } from 'nodemailer/lib/addressparser';
const Splitter = require('mailsplit').Splitter;
const Joiner = require('mailsplit').Joiner;
import { Config } from './Config';
import { prefixedLog } from './Logger';
import { MailQueue } from './MailQueue';

const log = prefixedLog('SMTPServer');

export class SMTPServer
{
    #server: NodeSMTP;
    #queue: MailQueue;
    #rateLimiter = new RateLimiterMemory({
        duration: Config.smtpRateLimitDuration,
        points: Config.smtpRateLimitLimit,
    });
    #authLimiter = new RateLimiterMemory({
        duration: Config.smtpAuthLimitDuration,
        points: Config.smtpAuthLimitLimit,
    });

    constructor(queue: MailQueue)
    {
        this.#queue = queue;
        this.#server = new NodeSMTP({
            onConnect: this.#onConnect,
            onClose: this.#onClose,
            onAuth: this.#onAuth,
            onMailFrom: this.#onMailFrom,
            onData: this.#onData,
            authOptional: !Config.smtpRequireAuth,
            banner: Config.smtpBanner ?? `SMTP2Graph ${VERSION}`,
            size: Config.smtpMaxSize,
            secure: Config.smtpSecure,
            key: Config.smtpTlsKey,
            cert: Config.smtpTlsCert,
            allowInsecureAuth: Config.smtpAllowTls?Config.smtpAllowInsecureAuth:true,
            disabledCommands: Config.smtpAllowTls?undefined:['STARTTLS'],
        });
    }

    listen()
    {
        return new Promise<void>((resolve, reject)=>{
            this.#server.on('error', reject);

            this.#server.listen(Config.smtpPort, Config.smtpListenIp, ()=>{
                log('info', `Server started on ${Config.smtpListenIp || 'any-ip'}:${Config.smtpPort}`, {
                    mode: Config.mode,
                    secure: Config.smtpSecure,
                    authRequired: Config.smtpRequireAuth,
                });
                this.#server.off('error', reject);
                this.#server.on('error', error=>{
                    log('error', `An error occured`, {error});
                });
                resolve();
            });
        });
    }

    #getSessionMeta(session: any)
    {
        return {
            sessionId: session.id,
            remoteAddress: session.remoteAddress,
            clientHostname: session.clientHostname,
            hostNameAppearsAs: session.hostNameAppearsAs,
            user: session.user,
            secure: session.secure,
        };
    }

    #onConnect: SMTPServerOptions['onConnect'] = (session, callback)=>
    {
        if(Config.isIpAllowed(session.remoteAddress))
        {
            log('info', `Connection accepted`, this.#getSessionMeta(session));
            this.#rateLimiter.consume('all').then((rateLimit)=>{
                callback();
            }).catch((rateLimit: RateLimiterRes)=>{
                log('warn', `Connection rejected by rate limiter`, {
                    ...this.#getSessionMeta(session),
                    retryAfterSeconds: Math.ceil(rateLimit.msBeforeNext/1000),
                });
                callback(new Error(`Rate limit exceeded. Try again in ${Math.ceil(rateLimit.msBeforeNext/1000)} seconds`));
            });
        }
        else
        {
            log('warn', `Connection rejected: IP not allowed`, this.#getSessionMeta(session));
            callback(new Error(`IP ${session.remoteAddress} is not allowed to connect`));
        }
    };

    #onAuth: SMTPServerOptions['onAuth'] = (auth, session, callback)=>
    {
        this.#authLimiter.consume(session.remoteAddress).then((rateLimit)=>{
            if(!auth.username || !auth.password)
            {
                log('warn', `Authentication rejected: unsupported method`, this.#getSessionMeta(session));
                callback(new Error('Unsupported authentication method'));
            }
            else if(Config.isUserAllowed(auth.username, auth.password))
            {
                log('info', `Authentication succeeded`, {
                    ...this.#getSessionMeta(session),
                    username: auth.username,
                });
                callback(null, {user: auth.username});
            }
            else
            {
                log('warn', `Authentication failed`, {
                    ...this.#getSessionMeta(session),
                    username: auth.username,
                });
                callback(new Error('Invalid login'));
            }
        }).catch((rateLimit: RateLimiterRes)=>{
            log('warn', `Authentication rejected by brute force protection`, {
                ...this.#getSessionMeta(session),
                retryAfterSeconds: Math.ceil(rateLimit.msBeforeNext/1000),
            });
            callback(new Error(`Too many failed logins`));
        });
    };

    #onClose: SMTPServerOptions['onClose'] = (session)=>
    {
        log('info', `Connection closed`, this.#getSessionMeta(session));
    };

    #onMailFrom: SMTPServerOptions['onMailFrom'] = (address, session, callback)=>
    {
        if(Config.isFromAllowed(address.address, session.user))
        {
            log('info', `MAIL FROM accepted`, {
                ...this.#getSessionMeta(session),
                from: address.address,
            });
            callback();
        }
        else
        {
            log('warn', `MAIL FROM rejected`, {
                ...this.#getSessionMeta(session),
                from: address.address,
            });
            callback(new Error(`FROM "${address.address}" not allowed`));
        }
    };

    #onData: SMTPServerOptions['onData'] = (stream, session, callback)=>
    {
        if(!session.envelope.mailFrom)
        {
            log('warn', `Message rejected: missing FROM`, this.#getSessionMeta(session));
            callback(new Error('Missing FROM'));
            return;
        }

        const mail = new MailComposer({
            messageId: session.id,
            raw: stream,
        });

        const mailFrom = session.envelope.mailFrom;

        // Inject BCC header if necessary
        const envelope = {...session.envelope}; // We need a copy, because the envelope object will get overwritten while parsing
        const messageMeta = {
            ...this.#getSessionMeta(session),
            from: mailFrom.address,
            recipients: envelope.rcptTo.map(rcpt=>rcpt.address),
            recipientCount: envelope.rcptTo.length,
        };
        const splitter = new Splitter();
        splitter.on('data', (data: any)=>{
            if(data.type === 'node')
            {
                // Inject from header if needed
                try {
                    if(!data.headers.hasHeader('From') && envelope.mailFrom)
                        data.headers.add('From', envelope.mailFrom.address);
                } catch(error) {
                    log('error', `Failed to inject from header`, {error});
                }

                // Inject bcc header if needed
                try {
                    if(!data.headers.hasHeader('Bcc')) // We don't have a BCC header?
                    {
                        // Collect all TO and CC recipients
                        const visibleRecipients: Address[] = [];
                        if(data.headers.hasHeader('To')) visibleRecipients.push(...addressparser(data.headers.get('To'), {flatten: true}));
                        if(data.headers.hasHeader('Cc')) visibleRecipients.push(...addressparser(data.headers.get('Cc'), {flatten: true}));

                        // Check if there are recipients missing from TO/CC, in that case we add them as BCC
                        const bcc = envelope.rcptTo.filter(rcpt=>!visibleRecipients.some(visible=>visible.address.toLowerCase()===rcpt.address.toLowerCase()));
                        if(bcc.length) data.headers.add('Bcc', bcc.map(r=>r.address).join(', '));
                    }
                } catch(error) {
                    log('error', `Failed to inject BCC header`, {error});
                }
            }
        });

        // Create the EML file
        const tmpFile = path.join(this.#queue.tempPath, `${session.id}.eml`);
        const writeStream = fs.createWriteStream(tmpFile);
        writeStream.on('error', error=>{
            log('error', `Failed writing queued message`, {...messageMeta, error, tmpFile});
        });
        const mailCompile = mail.compile();
        (mailCompile as any).keepBcc = true;
        mailCompile.createReadStream().pipe(splitter).pipe(new Joiner()).pipe(writeStream);

        // Windows can keep a handle open for a short time even after 'finish' fires.
        // the rename that occurs in MailQueue.add must wait until the underlying
        // file descriptor is closed, which is signalled by the 'close' event.
        writeStream.on('close', () => {
            if(stream.sizeExceeded)
            {
                log('warn', `Message rejected: size limit exceeded`, messageMeta);
                const err = new Error('Message exceeds fixed maximum message size');
                (<any>err).responseCode = 552;
                callback(err);

                try {
                    fs.unlinkSync(tmpFile);
                } catch {
                    // ignore, it may already be removed by cleanup logic
                }
            }
            else
            {
                callback();
                this.#queue.add(tmpFile);
                log('info', `Message accepted for delivery`, {
                    ...messageMeta,
                    queuedFile: path.basename(tmpFile),
                });
            }
        });

        // ensure the stream is ended when the mail compiles (pipe will do this for us,
        // but explictly listening for 'finish' lets us log/debug if needed)
        writeStream.on('finish', ()=>{
            log('verbose', 'EML write finished, waiting for close');
        });
    };
    
}
