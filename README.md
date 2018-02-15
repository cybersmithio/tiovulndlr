# tiovulndlr
A Python workflow automation for Tenable.io


# To Build
To build into a Docker file: **docker build ./ -t tiovulndlr88

# To Run

If a mongo DB doesn't already exist, use this command to create one: 
**docker run -d --name tiovulndb -p 27017:27017 mongo**

The above syntax still allows for inter-container linking, but also allows for debugging using a Mongo client



Run and attach to a Mongo DB in a container called "tiovulndb": 
**docker run -d --name tiovulndlr --link tiovulndb:mongo tiovulndlr**


If you want to customize the configuration without editing the container, you can mount a configuration of your own using a syntax like this: 
**docker run -d --name tiovulndlr -v /Users/jsmith/tiovulndlr-config.json:/usr/src/app/configuration/config.json:ro --link tiovulndb:mongo tiovulndlr**
