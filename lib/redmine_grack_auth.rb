require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'rack/auth/basic'
require 'open-uri'
require 'openssl'

OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE

class RedmineGrackAuth < Rack::Auth::Basic

  def valid?(auth, identifier, url)

    user, pass = *auth.credentials[0, 2]
    permission = (@req.request_method == "POST" && Regexp.new("(.*?)/git-receive-pack$").match(@req.path_info) ? 'rw' : 'r')

    begin
      r = /<membership><project [^>]*(name|identifier)="#{identifier}"/
      uri = "#{url}/users/current.xml?include=memberships"
      return false unless r.match(open(uri,
        :http_basic_authentication => [user, pass], 'User-Agent' => 'ruby').read())
    rescue OpenURI::HTTPError
      return false
    end
    return true
  end

  def call(env)
    @env = env  
    @req = Rack::Request.new(env)
    
    identifier = get_project()
    url = $grackConfig[:redmine]
    auth = Rack::Auth::Basic::Request.new(env)
    
    return unauthorized if(not defined?($grackConfig))
    return unauthorized if !identifier or !url
    return bad_request if !$grackConfig[:redmine]
    
    if auth.provided?
      return bad_request unless auth.basic?
      return unauthorized unless valid?(auth, identifier, url)
      env['REMOTE_USER'] = auth.username
      return @app.call(env)
    elsif @req.post? and @req.path_info.end_with?('git-receive-pack')
      return unauthorized
    else
      begin
        open("#{url}/projects/#{identifier}.xml")
      rescue OpenURI::HTTPError => err
        return bad_request unless err.io.status[0] == '401'
        return unauthorized
      end
      return @app.call(env)
    end
  end

  def get_project
    paths = ["(.*?)/git-upload-pack$", "(.*?)/git-receive-pack$", "(.*?)/info/refs$", "(.*?)/HEAD$", "(.*?)/objects" ]

    suburi = $grackConfig[:grack_suburi] || ''
    paths.each {|re|
      if m = Regexp.new(File.join('/', suburi, re)).match(@req.path)
        identifier = m[1][/([^\/]+)\.git/, 1]
        return (identifier == '' ? nil : identifier)
      end
    }

    return nil
  end

end
