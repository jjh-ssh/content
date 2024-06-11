PrivX provides a solution for granting just in time access only for the needed resources, often called Zero Trust access. The solution automates the process of granting and revoking access by integrating with an existing identity management system (it also comes with its own!) and ensures that the users have one click access to right infrastructure resources with correct privileges. It also provides full audit trail and monitoring which is vital if your users are handling sensitive data or if you need to provide access for 3rd parties to your environment. All access to enterprise resources is fully authenticated, fully authorized, and fully encrypted based upon device state and user credentials.

You can run PrivX either on-premise or in the cloud.

##### What does this pack do?
This integration helps accessing your SSH target host by fetching short-term certificates provided by PrivX:
privx-get-cert username=xsoar hostname=10.1.2.3

Fetch the certificate using privx-get-cert command, save it to a file and then access your target host with SSH client using the certificate:
ssh -i id-rsa -o CertificateFile=id_rsa-cert targetuser@targethost

The integration also allows you to fetch secrets via PrivX secrets vault:
privx-get-secret name=the-secret

