# Use an official Node.js runtime as a parent image
FROM node:22

# Install packages
RUN apt-get update && apt-get install -y gcc --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Copy flag
COPY flag.txt /root/flag
RUN chmod 644 /root/flag

# Setup flag reader
COPY config/readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

# Set the working directory in the container
WORKDIR /app

# Copy package.json
COPY ./src/package.json /app

# Install any needed packages specified in package.json
RUN npm install

# Copy challenge files
COPY ./src/ /app

# Create appuser
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Run the app when the container launches
CMD ["npm", "start"]
