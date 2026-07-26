# Email Management Guide

## Prerequisites

Before setting up email, make sure:

- **Port 25 is open** -- Many cloud providers (AWS, GCP, Azure, Oracle) block outbound port 25 by default. You may need to request an unblock from your provider, or use SMTP relay (see below).
- **rDNS / PTR record is set** -- Your server's IP must have a reverse DNS record pointing to a hostname (e.g., `mail.example.com`). Set this in your VPS provider's control panel (Vultr, Hetzner, DigitalOcean, etc.), not in your domain DNS.
- **A domain with DNS access** -- You need to add MX, SPF, DKIM, and DMARC records.

Check if port 25 is open:

```bash
telnet smtp.gmail.com 25
```

If the connection times out, port 25 is blocked on your network.

## One-Click Install

DockPanel installs a complete mail server stack with one click.

1. Go to **Mail** in the sidebar
2. If the mail server is not installed, click **Install Mail Server**
3. DockPanel installs and configures:
   - **Postfix** -- SMTP server for sending and receiving email
   - **Dovecot** -- IMAP/POP3 server for reading email
   - **OpenDKIM** -- DKIM signing for email authentication

The installation takes about 30 seconds. It also opens the mail ports (25, 587, 465, 143, 993,
110, 995) in the firewall, sets Postfix's HELO name from your panel domain, and hands Dovecot
your Let's Encrypt certificate if the box has one.

### One thing DockPanel cannot do for you: reverse DNS

Set a **PTR record** for your server's IP, pointing at your mail hostname. Only whoever owns
the IP can do this -- your hosting provider, usually under "reverse DNS" in their control
panel. Without it receivers add a spam score for an unknown sending host no matter how good
your SPF, DKIM and DMARC are: on a freshly-installed test box, the missing PTR was worth 2.5
points on its own once everything else was correct.

## Add a Mail Domain

1. Go to **Mail** > **Domains**
2. Click **Add Domain**
3. Enter your domain name: `example.com`
4. DockPanel generates the DKIM keys and shows the DNS records you need to add

## DNS Records

After adding a mail domain, you must add these DNS records at your domain registrar or DNS provider.

**Read them from the panel, not from here.** Open the domain, go to the **DNS Records** tab, and copy each record — every field is copyable and each one is marked *published* or *missing* once you press **Verify DNS**. The values depend on your server's address and on the DKIM key generated for your domain, so a page like this one cannot state them without going stale.

This guide used to spell the records out, and every one of them was wrong in some way by the time you read it: it named the DKIM selector `default` when DockPanel has always used `dockpanel`, and it described the mail host as `mail.example.com` when the records DockPanel publishes use the domain itself. Following it produced a DKIM record that could never verify.

What the panel gives you, and why each one exists:

| Record | What it does |
|---|---|
| `A` | The address other mail servers connect to. Must not be proxied. |
| `MX` | Where mail for this domain is delivered. |
| `TXT` (SPF) | Authorises this server to send mail for the domain. |
| `TXT` (DKIM) | The public key receivers use to verify our signature. |
| `TXT` (DMARC) | Tells receivers what to do when SPF or DKIM fails. |

If DockPanel manages the domain's DNS zone, these are created for you when you add the domain — there is nothing to copy.

### Checking them

**Verify DNS** on the same tab checks that each record resolves *and points at this server*, rather than merely that something exists. A domain whose MX belongs to another provider is reported as such. See [What DockPanel checks for you](prerequisites.md) for the full behaviour, including what happens when a lookup cannot be run at all.

### DMARC policy

DockPanel suggests `p=quarantine`, which asks receivers to flag suspicious mail. Once you have confirmed everything works, tightening it to `p=reject` (block spoofed email outright) is a change worth making by hand at your DNS provider.

## Create Mailboxes

1. Go to **Mail** > **Mailboxes**
2. Click **Add Mailbox**
3. Enter:
   - **Email address**: `user@example.com`
   - **Password**: A strong password
   - **Quota** (optional): Storage limit in MB
4. Click **Create**

You can also create:

- **Aliases** -- Forward `info@example.com` to `user@example.com`
- **Catch-all** -- Route all unmatched addresses to a single mailbox
- **Autoresponders** -- Out-of-office or auto-reply messages

## Test Sending and Receiving

### Test sending

Send a test email from the server:

```bash
echo "Test from DockPanel mail server" | mail -s "Test Email" recipient@gmail.com
```

Or use the mail queue viewer in the panel (Mail > Queue) to monitor outgoing messages.

### Test receiving

Send an email from an external account (Gmail, Outlook) to `user@example.com` and check:

1. The mailbox in the panel (Mail > Mailboxes > user@example.com)
2. Or connect with an IMAP client (Thunderbird, Outlook) using:
   - **IMAP server**: `mail.example.com`
   - **Port**: `993` (SSL/TLS)
   - **Username**: `user@example.com`
   - **Password**: The mailbox password

### Verify DNS records

Press **Verify DNS** on the domain's DNS Records tab — that checks the records point at *this* server, which a raw lookup cannot tell you.

To check by hand, substituting your own domain (and noting that DockPanel's DKIM selector is `dockpanel`, not the `default` many guides assume):

- **MX**: `dig MX example.com +short`
- **SPF**: `dig TXT example.com +short`
- **DKIM**: `dig TXT dockpanel._domainkey.example.com +short`
- **DMARC**: `dig TXT _dmarc.example.com +short`

Use [mail-tester.com](https://www.mail-tester.com) to check your overall email deliverability score.

## SMTP Relay

If your provider blocks port 25 (most cloud providers do), configure an SMTP relay to send email through a third-party service.

Supported relay providers: SendGrid, Mailgun, Amazon SES, Brevo, or any SMTP server.

1. Go to **Mail** > **Settings**
2. Enable **SMTP Relay**
3. Enter relay credentials:
   - **SMTP host**: `smtp.sendgrid.net`
   - **Port**: `587`
   - **Username**: `apikey`
   - **Password**: Your SendGrid API key
4. Save

DockPanel configures Postfix to route all outbound email through the relay. Incoming email still arrives directly to your server (port 25 inbound is not blocked by providers, only outbound).

## Webmail (Roundcube)

Roundcube provides browser-based email access.

1. Go to **Docker Apps**
2. Search for **Roundcube**
3. Click **Deploy**
4. Set a domain (e.g., `webmail.example.com`)

After deployment, users can access their email at `https://webmail.example.com`.

## Spam Filter (Rspamd)

Rspamd provides spam filtering, greylisting, and DKIM verification for incoming mail.

1. Go to **Docker Apps**
2. Search for **Rspamd**
3. Click **Deploy**

Rspamd includes a web interface for viewing spam statistics and adjusting filter rules.
