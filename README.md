# maildaily-cloud
Organize all the emails you received today at a set time each day and sort them into categories
Once enabled, the title, excerpts, to-dos, and quick view of the current brief will be sent to Google Translate, without sending email authorization tokens or attachments. If the translation fails, the original text will still be shown. 

The translations are encrypted and cached in your own database, up to 30 entries; disconnecting and deleting the account will delete the translations. 

Each request can be up to 50,000 characters, and the app allows up to 300,000 characters per UTC calendar month, with failed attempts also counted. Free Render may reset the cache and count if data is lost, so this shouldn't be taken as a hard billing limit. Translation counts don't include email content and are preserved if the account is deleted.
