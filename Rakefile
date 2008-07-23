require 'rubygems'
Gem::manage_gems
require 'rake/gempackagetask'
require 'rake/rdoctask'

spec = Gem::Specification.new do |gem|
	gem.name     = "activedirectory"
	gem.version  = "0.9.1"
	gem.date     = "2008-07-23"
	gem.summary  = "An interface library for accessing Microsoft's Active Directory."
	gem.description = "ActiveDirectory uses Net::LDAP to provide a means of accessing and modifying an Active Directory data store."

	gem.specification_version = 2 if gem.respond_to? :specification_version=

	gem.platform = Gem::Platform::RUBY
	gem.author   = "James R Hunt"
	gem.email    = "james@niftylogic.net"
	gem.homepage = "http://gems.niftylogic.net/activedirectory"

	gem.files        = FileList["lib/**/*.rb"]
	gem.require_path = "lib"
	gem.has_rdoc     = true

	gem.add_dependency("ruby-net-ldap", [">= 0.0.4"])
end

Rake::GemPackageTask.new(spec) do |pkg|
	pkg.gem_spec = spec
end

Rake::RDocTask.new do |rdoc|
	rdoc.main = "README"
	rdoc.rdoc_files.include("README", "lib/**/*.rb")
end
