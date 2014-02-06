class Account < Sequel::Model
  MINIMUM_PASSWORD_LENGTH = 5
  MINIMUM_PASSWORD_HINT_LENGTH = 2
  EMAIL_VALIDATION_REGEX = /\A[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+\z/i

  one_to_many :receive_addresses

  class << self
    def valid_login?(email, plaintext)
      account = self[email: email]
      return false if account.nil?
      account.valid_password? plaintext
    end

    def bcrypt_cost
      @bcrypt_cost
    end

    def bcrypt_cost=(cost)
      @bcrypt_cost = cost
    end
  end
  
  def valid_password?(plaintext)
    BCrypt::Password.new(values[:password]) == plaintext
  end

  def password=(plaintext)
    @password_length = plaintext.nil? ? 0 : plaintext.length
    @password_plaintext = plaintext
    values[:password] = BCrypt::Password.create plaintext, cost: (self.class.bcrypt_cost || BCrypt::Engine::DEFAULT_COST)
  end

  def generate_password_token
    token = SecureRandom.hex(16)
    self.update(:password_token => token)
    token
  end

  def reset_password(new_password)
    self.password = new_password
    self.password_token = nil
    self.save
  end

  def validate
    super

    if values[:email].nil? || values[:email].empty? || values[:email].match(EMAIL_VALIDATION_REGEX).nil?
      errors.add :email, 'valid email address is required'
    end

    # Check for existing user
    user = self.class.select(:id).filter(email: values[:email]).first
    if !user.nil? && (user.id != values[:id])
      errors.add :email, 'this email address is already taken'
    end

    if values[:password].nil? || (@password_length && @password_length < MINIMUM_PASSWORD_LENGTH)
      errors.add :password, "password must be at least #{MINIMUM_PASSWORD_LENGTH} characters" 
    end

    if values[:password_hint].nil? || values[:password_hint].empty? || values[:password_hint].length < MINIMUM_PASSWORD_HINT_LENGTH
      errors.add :password_hint, "password hint must be at least #{MINIMUM_PASSWORD_HINT_LENGTH} characters"
    end
  end
end