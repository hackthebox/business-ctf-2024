# Use an official Node.js runtime as a parent image
FROM node:22

# Set the working directory in the container
WORKDIR /app

# Copy package.json
COPY ./src/package.json /app

# Install any needed packages specified in package.json
RUN npm install

# Copy challenge files
COPY ./src/ /app

# Run the app when the container launches
CMD ["npm", "start"]