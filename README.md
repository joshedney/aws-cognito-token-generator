# Generate token for AWS Cognito

Code for a lambda function/api gateway to take a username and password from a Cognito pool and generate a ID_Token and Refresh_Token.


## Usage
`curl -XPOST --data '{"username": "Bob", "password": "Ross"}' https://api.eu-west-1.amazonaws.com/prod/oauth`
