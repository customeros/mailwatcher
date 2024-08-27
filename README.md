<br /><br />

<p align="center"><img align="center" src="https://customer-os.imgix.net/companies/logos/mailwatcher_logo.png" height="200" alt="mailwatcher" /></p>
<h1 align="center">MailWatcher</h1>
<h4 align="center">A CLI for monitoring mailbox and mailserver health</h4>

<br /><br /><br />

## 👉 Live Demo: https://customeros.ai

This is open-source, but we also offer a hosted API that's simple to use. If you are interested, find out more at [CustomerOS](https://docs.customeros.ai/api-reference/verify/verify-an-email-address). If you have any questions, you can contact me at matt@customeros.ai.

<br />

## Quickstart 

1. Download the appropriate CLI tarball for your OS:

```
wget mailwatcher.sh/mailwatcher-linux-arm64.tar.gz
wget mailwatcher.sh/mailwatcher-linux-amd64.tar.gz
wget mailwatcher.sh/mailwatcher-macos.tar.gz
```

2. Extract the binary:

```
tar -xzf filename.tar.gz
```

3. Set the `MAIL_SERVER_DOMAIN` environment variable.  See the `Mail Server setup guide` section below for more details:

```
export MAIL_SERVER_DOMAIN=example.com
```

4. Test to make sure everything is working

```
./mailwatcher version
```

