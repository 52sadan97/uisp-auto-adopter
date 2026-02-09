# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Define environment variable for data persistence
ENV DATA_DIR=/data

# Create the data directory
RUN mkdir -p /data

# Volume configuration to persist data
VOLUME ["/data"]

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5050 available to the world outside this container
EXPOSE 5050

# Define environment variable
ENV NAME uisp-auto-adopter

# Run automatically the dashboard
CMD ["python", "web_dashboard.py"]
