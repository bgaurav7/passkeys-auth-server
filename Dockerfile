# Use latest node version 22.x
FROM node:22

# create app directory in container
RUN mkdir -p /app

# set /app directory as default working directory
WORKDIR /app

# only copy package.json initially so that `RUN yarn` layer is recreated only
# if there are changes in package.json
ADD package.json /app/

# --pure-lockfile: Don’t generate a yarn.lock lockfile
RUN npm install

# copy all file from current dir to /app in container
COPY . /app/

# expose port 3000
EXPOSE 3000

# cmd to start service
CMD [ "npm", "start" ]