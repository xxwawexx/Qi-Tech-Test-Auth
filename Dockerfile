FROM php:7.4-fpm

# Install git, unzip, libzip-dev, and libgmp-dev
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libzip-dev \
    libgmp-dev

# Install zip and gmp PHP extensions
RUN docker-php-ext-install zip gmp

# Install Composer
COPY --from=composer /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy files from your project to the Docker image
COPY . .

# Run composer install to install the dependencies
RUN composer install

# Expose port 9000 and start php-fpm server
EXPOSE 9000
CMD ["php-fpm"]
