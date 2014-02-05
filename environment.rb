ENV['RACK_ENV'] ||= 'development'
ENV['TZ'] = 'UTC'
DIR_ROOT = File.expand_path File.dirname(__FILE__)
Encoding.default_internal = 'UTF-8'

require 'yaml'
require 'json'
require "rack/protection"

Bundler.require
Bundler.require :development if ENV['RACK_ENV'] == 'development'

$config = YAML.load_file(File.join(DIR_ROOT, 'config.yml'))[ENV['RACK_ENV']]

DB = Sequel.connect $config['database']

Dir.glob('workers/*.rb').each {|w| require File.join(DIR_ROOT, "/#{w}") }

if defined?(Pry)
  Pry.commands.alias_command 'c', 'continue'
  Pry.commands.alias_command 's', 'step'
  Pry.commands.alias_command 'n', 'next'
  Pry.commands.alias_command 'f', 'finish'
end

Sequel.datetime_class = Time
Sequel.extension :named_timezones
Sequel.extension :thread_local_timezones
Sequel.extension :pagination
Sequel.extension :migration
Sequel::Model.plugin :validation_helpers
Sequel::Model.plugin :force_encoding, 'UTF-8'
Sequel::Model.plugin :timestamps, create: :created_at, update: :updated_at
Sequel::Model.plugin :defaults_setter
Sequel.default_timezone = 'UTC'
Sequel::Migrator.apply DB, './migrations'

Dir.glob('models/*.rb').each {|m| require File.join(DIR_ROOT, "#{m}") }

DB.loggers << Logger.new(STDOUT) if ENV['RACK_ENV'] == 'development'
