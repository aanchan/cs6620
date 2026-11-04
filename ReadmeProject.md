How to run project.

Prereqs:
    - Run `aws configure` and set creditonals
    - Run `aws configure set aws_session_token [session_token]`

1. DynamoDB
    - `cd cs6620/terraform`
    - `terraform init` apply each time a change to terraform code or backend occurs
    - `terraform validate` ensures the terraform configure is valid
    - `terraform plan` proposes changes
    - `terraform apply` launches program and creates table

2. Server.js
    - `cd cs6620/api`
    - `unset DYNAMODB_ENDPOINT` ensures the program connects to an AWS instance in stead of local db
    - `npm start`

    Request Examples
        [targets](http://localhost:3001/targets)
            curl -i -X POST http://localhost:3001/targets \
            -H 'Content-Type: application/json' \
            -d '{"url":"https://api.example.com/users","frequency":"daily","email":"dev@example.com"}'

3. React Website
    - Make sure the target api is running too.
    - `cd cs6620/web`
    - `npm install` if first time or pulled changes
    - `npm run dev` runs app