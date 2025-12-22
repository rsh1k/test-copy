`private-issues`

A private repo to store Github issues that might need to contain non-public info so that they don't become public by way of default in dotcms/core.

`Github Project`

We purposely decided not to create a separate github project for these issues because it’s hard to keep everything in sync. At time of writing, our desired approach is to use a private repo for issues that have some sensitivity on them and to assign those issues to our standard [dotCMS - Product Planning](url project. Although the dotCMS - project Planning project is public, issues that belong to a private repo remain invisible to those without permissions.

`Labels`

Labels will be tricky. They are one of the things that we need to manually keep in sync. For the initial import of labels to this repo, I used the github CLI.

``gh label clone dotcms/core -R dotcms/cloud-engineering-issues``
