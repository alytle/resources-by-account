# resources-by-account
Describe AWS Resources in each account in the AWS Organization.

## Usage

There must be a Role in each account with the same name, and the account under which the script is executed must have permissions to AssumeRole.

```
python list_resources.py --output results.csv --rolename RoleName
```

