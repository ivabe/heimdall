# Heimdall

Heimdall is a SSI framework based on generic ZKPs.

# heimdalljs

## Install
- Install nodejs(@v16.0.0) and npm (@7.10.0)
- Go to heimdalljs
- Install dependencies `npm install`
- Link the package to the path `sudo npm link`
- Heimdall is now available by the command `heimdalljs`

## Docker
- Install both `docker` and `docker-compose`
- Build `docker-compose build`
- Up `docker-compose up`
- Jump inside the container `docker exec -ti heimdall bash`
- Use heimdalljs as a container `docker-compose run heimdall heimdalljs key -h`

## API Boostrap with Docker
- Install both `docker` and `docker-compose`
- Build `docker-compose build`
- Up `docker-compose up`
- Jump inside `./heimdalljs/test/restful`
- See the `test.env` file - get an auth token from GitHub (you need to have write access to `https://github.com/ermolaev1337/test-revoc`)
- Create `.env` file and put there the token as a var `GITHUB_TOKEN`
- Run `restful-run.sh`
- See the output files in the directory `./heimdalljs/test/restful`

## Test
- Run Mocha tests for Heimdalljs `cd heimdalljs && npm i && npm run test`
- Run Mocha tests for Circom `cd circom && npm i && npm run test`

## Usage
The files example-run.sh provide an example run for heimdalljs using the individual presentation types. Run and inspect the scripts. They are located in heimdalljs/test/*

## Circom
The circuits of the presentations are located in the folder circom. These are not required for the usage of heimdalljs since their resulting ZKeys are stored in heimdalljs/zkp. 
