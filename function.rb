# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

# TODO Don't hard-code HTTP response numbers.
# TODO Don't hard-code HTTP response strings.
# TODO How to check if authorization header is properly formatted?

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

  # HTTP headers are case-insensitive.
  http_headers = event['headers'].transform_keys(&:downcase)
  content_type = http_headers['content-type']
  authorization = http_headers['authorization']
  body = event['body']
  path = event['path']
  http_method = event['httpMethod']

  if !is_path_allowed(path)
    return response(body: { error: 'Not found' }, status: 404)
  end
  if !is_method_allowed(path, http_method)
    return response(body: { error: 'Method not allowed' }, status: 405)
  end
  if path == '/auth/token' && content_type != 'application/json'
    return response(body: { error: 'Unsupported media type' }, status: 415)
  end

  if path == '/auth/token' && body.nil?
    return response(body: { error: 'Unprocessable content' }, status: 422)
  end
  if path == '/auth/token' && !is_valid_json(body)
    return response(body: { error: 'Unprocessable content' }, status: 422)
  end
  if path == '/auth/token'
    payload = {
      data: JSON.parse(body),
      exp: Time.now.to_i + 5,
      nbf: Time.now.to_i + 2
    }
    token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
    return response(body: { "token": token}, status: 201)
  end

  if path == '/' && authorization == nil
    return response(body: { error: 'Forbidden' }, status: 403)
  end
  if path == '/' && (!(authorization.start_with?('Bearer ')) || authorization.empty? || !authorization.include?('.'))
    return response(body: { error: 'Forbidden' }, status: 403)
  end

  authorization.slice!('Bearer ')

  begin
    decoded_token = JWT.decode(authorization, ENV['JWT_SECRET'], true, { algorithm: 'HS256' })
  rescue JWT::ImmatureSignature
    return response(body: { error: 'ImmatureSignature' }, status: 401)
  rescue JWT::ExpiredSignature
    return response(body: { error: 'ExpiredSignature' }, status: 401)
  rescue JWT::VerificationError
    return response(body: { error: 'VerificationError' }, status: 403)
  rescue JWT::DecodeError => e
    return response(body: { error: 'DecodeError' }, status: 403)
  end

  response(body: decoded_token[0]['data'], status: 200)
end

def is_valid_json(body)
  begin
    JSON.parse(body)
    true
  rescue JSON::ParserError
    false
  end
end

def is_method_allowed(path, http_method)
  if path == '/' && http_method == 'GET'
    return true
  elsif path == '/auth/token' && http_method == 'POST'
    return true
  else
    return false
  end
end

def is_path_allowed(path)
  path == '/' || path == '/auth/token'
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # What happens when a give an empty body?
  PP.pp main(context: {}, event: {
    'body' => '',
    'headers' => { 'Content-Type' => 'application/json' },
    'httpMethod' => 'POST',
    'path' => '/auth/token'
  })

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/auth/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  # PP.pp main(context: {}, event: {
  #              'headers' => { 'Authorization' => "Bearer #{token}",
  #              'Content-Type' => 'application/json' },
  #              'httpMethod' => 'GET',
  #              'path' => '/'
  #            })
  PP.pp main(context: {}, event: {
    'headers' => { 'Authorization' => "",
    'Content-Type' => 'application/json' },
    'httpMethod' => 'GET',
    'path' => '/'
  })
end
