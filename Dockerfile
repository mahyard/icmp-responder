# Stage 1: Build the application
FROM alpine:3.20 AS builder

# Install build dependencies
RUN apk add --no-cache g++ musl-dev libnetfilter_queue-dev

# Set working directory and copy the source code
WORKDIR /app
COPY main.cpp .

# Compile the C++ application
RUN g++ main.cpp -o icmp-responder -lnetfilter_queue

# Stage 2: Create the runtime image
FROM alpine:3.20

# Install only the runtime library needed
RUN apk add --no-cache libnetfilter_queue libstdc++

# Copy the compiled binary from the builder stage
COPY --from=builder /app/icmp-responder /icmp-responder

# Set the default command to run the application
ENTRYPOINT ["/icmp-responder"]
