# Cloud Identity Authentication as a Service Demo App
This repository contains a NodeJS Express application which uses IBM Cloud Identity REST APIs to perform all authentication functions.

The following are included:
- Username & Password Authentication
- QR Code Login
- E-mail and SMS One Time Password

## Set up
Clone this repository to your machine (or download a zip and extract)

Install the required NodeJS modules:

`npm install`

Copy the sample environment file to .env

`cp dotenv.template .env`

Edit the `.env` and complete for you Cloud Identity environment.  Here is a sample:

```
TENANT_URL=https://yourtenantid.ice.ibmcloud.com
CLIENT_ID=xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=yyyyyyyyyy
VERIFY_REG_ID=zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz
SESSION_SECRET=my_super_secret
```

The CLIENT_ID and CLIENT_SECRET must be for an API Client that has these permissions (found under Configuration-->API Access):
- Authenticate any user
- Read authenticator registrations for all users
- Read second-factor authentication enrollment for all users
- Read users and groups

The VERIFY_REG_ID is the Id of a Registration profile (found under Security-->Registration Profiles)

To use QR Code Login, your user must have a registered IBM Verify application.  This can be done via the Cloud Identity Launchpad.  Registration is not supported in the demonstration application.

Run the application:

`npm start`

Connect to the application at `http://localhost:3000`

# License

The contents of this repository are open-source under the Apache 2.0 licence.

```
Copyright 2019 International Business Machines

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
