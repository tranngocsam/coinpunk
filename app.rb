require File.join(File.expand_path(File.dirname(__FILE__)), 'environment.rb')

class App < Sinatra::Base
  MINIMUM_SEND_CONFIRMATIONS = 0

  register Sinatra::Flash

  configure do
    $bitcoin = Silkroad::Client.new(
      $config['bitcoind_rpcuser'],
      $config['bitcoind_rpcpassword'],
      url: $config['bitcoind_rpchost']
    )

    use Rack::Session::Cookie, key:          'website',
                               path:         '/',
                               expire_after: 31556926, # one year in seconds
                               secret:       $config['session_secret']

    use Rack::TimeZoneHeader # TODO this I believe is deprecated

    error     { slim :error }      if production?
    not_found { slim :not_found }  if production?
  end

  use Rack::Protection::AuthenticityToken
  use Rack::Recaptcha, :public_key => $config['recaptcha_public_key'], :private_key => $config['recaptcha_private_key']
  helpers Rack::Recaptcha::Helpers

  Pony.options = {
    :from => 'noreply@telesocial.com',
    :via => :smtp,
    :via_options => {
      :address              => 'smtp.gmail.com',
      :port                 => '587',
      :enable_starttls_auto => true,
      :user_name            => $config["mailer_username"],
      :password             => $config["mailer_password"],
      :authentication       => :plain, 
      :domain               => "telesocial.com"
    }
  }

  before do
    @timezone_name = session[:timezone]
    @host_url = $config["host_url"]
    session[:csrf] = session["_csrf_token"] ||= SecureRandom.hex(16)

    if @timezone_name
      @timezone = TZInfo::Timezone.get(@timezone_name)
      @timezone_identifier = @timezone.current_period.zone_identifier
      @timezone_offset = @timezone.current_period.utc_total_offset
    end
  end

  get '/' do
    dashboard_if_signed_in
    slim :index
  end

  get '/dashboard' do
    require_login

    @title = 'Dashboard'

    account = Account[email: session[:account_email]]

    addresses_raw, transactions_raw, account_balance_raw = $bitcoin.batch do |client|
      client.rpc 'getaddressesbyaccount', account.email
      client.rpc 'listtransactions', account.email
      client.rpc 'getbalance', account.email
    end

    @addresses_received = $bitcoin.batch do
      addresses_raw['result'].each {|a| rpc 'getreceivedbyaddress', a}
    end.collect{|a| a['result']}

    @account            = account
    @addresses          = addresses_raw['result']
    @transactions       = transactions_raw['result']
    @account_balance    = account_balance_raw['result']

    slim :dashboard
  end

  post '/send' do
    require_login

    begin
      transaction_id = bitcoin_rpc(
        'sendfrom',
        session[:account_email],
        params[:tobitcoinaddress],
        params[:amount].to_f,
        MINIMUM_SEND_CONFIRMATIONS,
        params[:comment],
        params[:'comment-to']
      )
    rescue Silkroad::Client::Error => e
      flash[:error] = "Unable to send bitcoins: #{e.message}"
      redirect '/'
    end

    flash[:success] = "Sent #{params[:amount]} BTC to #{params[:tobitcoinaddress]}."
    redirect '/'
  end

  get '/transaction/:txid' do
    require_login
    @transaction = bitcoin_rpc 'gettransaction', params[:txid]
    slim :'transactions/view'
  end

  get '/accounts/new' do
    dashboard_if_signed_in
    @account = Account.new
    slim :'accounts/new'
  end

  post '/accounts/signin' do
    is_captcha_valid = recaptcha_valid?

    if is_captcha_valid && Account.valid_login?(params[:email], params[:password])
      session[:account_email] = params[:email]
      redirect '/dashboard'
    else
      if is_captcha_valid
        flash[:error] = 'Invalid login.'
      else
        flash[:error] = "Invalid captcha."
      end

      # Not sure what's wrong here, but if we don't have this line, message will not be displayed.
      flash[:error]
      redirect '/'
    end
  end

  post '/accounts/create' do
    dashboard_if_signed_in

    @account = Account.new email: params[:email], password: params[:password], :password_hint => params[:password_hint]
    is_captcha_valid = recaptcha_valid?
    if is_captcha_valid && params[:email] == params[:confirm_email] && params[:password] == params[:confirm_password] &&
          params[:password_hint] == params[:confirm_password_hint]
      if @account.valid?

        DB.transaction do
          @account.save
          address = bitcoin_rpc 'getaccountaddress', params[:email]
          @account.add_receive_address name: 'Default', bitcoin_address: address
        end

        Pony.mail(:to => @account.email, :subject => "Welcome to Telesocial", :html_body => (slim :"pony/welcome"))
        session[:account_email] = @account.email
        flash[:success] = 'Account successfully created!'
        redirect '/dashboard'
      else
        slim :'accounts/new'
      end
    else
      if is_captcha_valid
        if params[:email] != params[:confirm_email]
          flash[:error] = "Confirm email does not match."
        elsif params[:password] != params[:confirm_password]
          flash[:error] = "Confirm password does not match."
        else
          flash[:error] = "Confirm password hint does not match."
        end
      else
        flash[:error] = "Invalid captcha."
      end

      # Not sure what's wrong here, but if we don't have this line, message will not be displayed.
      flash[:error]
      slim :"accounts/new"
    end
  end

  get "/accounts/forgot-password" do
    slim :"accounts/forgot_password"
  end

  post "/accounts/forgot-password" do
    is_captcha_valid = recaptcha_valid?
    if is_captcha_valid && params[:password_hint].kind_of?(String) && 
          params[:email].kind_of?(String) && params[:email] =~ Account::EMAIL_VALIDATION_REGEX
      account = Account[email: params[:email]]

      if account && account.password_hint.downcase == params[:password_hint].downcase
        @token = account.generate_password_token
        Pony.mail(:to => account.email, :subject => "Password reset instruction", :html_body => (slim :"pony/forgot_password"))

        flash[:success] = "A reset password instruction was sent to your email, please check it to reset your password"
        redirect "/"
      elsif account
        flash[:error] = "Password hint is not correct"
        flash[:error]
        slim :"accounts/forgot_password"
      else
        # Puts this message here, so that no one can find out that the email is in the system or not.
        flash[:success] = "A reset password instruction was sent to your email, please check it to reset your password"
        redirect "/"
      end
    else
      if is_captcha_valid
        flash[:error] = "Invalid email."
      else
        flash[:error] = "Invalid captcha"
      end

      # Not sure what's wrong here, but if we don't have this line, message will not be displayed.
      flash[:error]
      slim :"accounts/forgot_password"
    end
  end

  get "/accounts/reset-password/:token" do
    @token = params[:token]
    slim :"accounts/reset_password"
  end

  post "/accounts/reset-password" do
    token = params[:token]
    is_captcha_valid = recaptcha_valid?

    if is_captcha_valid && params[:password] == params[:confirm_password]
      account = Account[password_token: token]
      if account && account.updated_at.to_time.to_i > Time.now.to_i - $config["password_token_lifetime"].to_i*60
        account.reset_password(params[:password])
        flash[:success] = "Your password was changed successfully"
        redirect "/"
      else
        flash[:error] = "Token was expired"
        flash[:error]
        redirect "/"
      end
    else
      if is_captcha_valid
        flash[:error] = "Confirm password does not match"
      else
        flash[:error] = "Invalid captcha"
      end

      # Not sure what's wrong here, but if we don't have this line, message will not be displayed.
      flash[:error]
      slim :"accounts/reset_password"
    end
  end

  post '/addresses/create' do
    require_login
    address = bitcoin_rpc 'getnewaddress', session[:account_email]
    Account[email: session[:account_email]].add_receive_address name: params[:name], bitcoin_address: address
    flash[:success] = "Created new receive address \"#{params[:name]}\" with address \"#{address}\"."
    redirect '/dashboard'
  end

  post '/set_timezone' do
    session[:timezone] = params[:name]
  end

  get '/signout' do
    require_login
    session[:account_email] = nil
    session[:timezone] = nil
    redirect '/'
  end

  def dashboard_if_signed_in
    redirect '/dashboard' if signed_in?
  end

  def require_login
    redirect '/' unless signed_in?
  end

  def signed_in?
    !session[:account_email].nil?
  end

  def bitcoin_rpc(meth, *args)
    $bitcoin.rpc(meth, *args)
  end

  def render(engine, data, options = {}, locals = {}, &block)
    options.merge!(pretty: self.class.development?) if engine == :slim && options[:pretty].nil?
    super engine, data, options, locals, &block
  end

  helpers do
    def timestamp_to_formatted_time(timestamp)
      return '' if timestamp.nil?
      Time.at(timestamp).getlocal(@timezone_offset).strftime('%b %-d, %Y %H:%M '+@timezone_identifier.to_s)
    end

    def format_amount(amount)
      ("%.6f" % amount).sub(/\.?0*$/, "")
    end
  end
end
