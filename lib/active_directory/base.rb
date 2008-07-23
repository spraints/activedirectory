#--
# Ruby/ActiveDirectory : Active Directory Interface for Ruby
#
# Copyright (c) 2006-2008 James R. Hunt <james@niftylogic.net>
#++

module ActiveDirectory
	#
	# Base class for all Ruby/ActiveDirectory Entry Objects (like User and Group)
	#
	class Base
		#
		# A Net::LDAP::Filter object that doesn't do any filtering (outside of
		# check that the CN attribute is present.  This is used internally for
		# specifying a 'no filter' condition for methods that require a filter
		# object.
		#
		NIL_FILTER = Net::LDAP::Filter.pres('cn')

		@@ldap = nil

		#
		# Configures the connection for the Ruby/ActiveDirectory library.
		#
		# For example:
		#
		#   ActiveDirectory::Base.setup(
		#     :host => 'domain_controller1.example.org',
		#     :port => 389,
		#     :base => 'dc=example,dc=org',
		#     :auth => {
		#       :username => 'querying_user@example.org',
		#       :password => 'querying_users_password'
		#     }
		#   )
		#
		# This will configure Ruby/ActiveDirectory to connect to the domain
		# controller at domain_controller1.example.org, using port 389. The
		# domain's base LDAP dn is expected to be 'dc=example,dc=org', and
		# Ruby/ActiveDirectory will try to bind as the querying_user@example.org
		# user, using the supplied password.
		#
		# Currently, there can be only one active connection per execution context.
		#
		# For more advanced options, refer to the Net::LDAP.new documentation.
		#
		def self.setup(settings)
			@@settings = settings
			@@ldap = Net::LDAP.new(settings)
		end

		def self.error
			"#{@@ldap.get_operation_result.code}: #{@@ldap.get_operation_result.message}"
		end

		def self.filter # :nodoc:
			NIL_FILTER 
		end

		def self.required_attributes # :nodoc:
			{}
		end

		#
		# Check to see if any entries matching the passed criteria exists.
		#
		# Filters should be passed as a hash of attribute_name => expected_value,
		# like:
		#
		#   User.exists?(
		#     :sn => 'Hunt',
		#     :givenName => 'James'
		#   )
		#
		# which will return true if one or more User entries have an sn (surname)
		# of exactly 'Hunt' and a givenName (first name) of exactly 'Hunt'.
		#
		# Partial attribute matches are available.	For instance,
		#
		#   Group.exists?(
		#     :description => 'OldGroup_*'
		#   )
		#
		# would return true if there are any Group objects in Active Directory
		# whose descriptions start with OldGroup_, like OldGroup_Reporting, or
		# OldGroup_Admins.
		#
		# (Note that the * wildcard matches zero or more characters, so the above
		# query would also return true if a group names 'OldGroup_' exists)
		# 
		def self.exists?(filter_as_hash)
			criteria = make_filter_from_hash(filter_as_hash) & filter
			(@@ldap.search(:filter => criteria).size > 0)
		end

		#
		# Whether or not the entry has local changes that have not yet been
		# replicated to the Active Directory server via a call to Base#save
		#
		def changed?
			!@attributes.empty?
		end

		def self.make_filter_from_hash(filter_as_hash) # :nodoc:
			return NIL_FILTER if filter_as_hash.nil? || filter_as_hash.empty?
			keys = filter_as_hash.keys

			first_key = keys.delete(keys[0])
			f = Net::LDAP::Filter.eq(first_key, filter_as_hash[first_key].to_s)
			keys.each do |key|
				f = f & Net::LDAP::Filter.eq(key, filter_as_hash[key].to_s)
			end
			f
		end

		#
		# Performs a search on the Active Directory store, with similar syntax
		# to the ActiveRecord#find method.
		#
		# The first argument passed should be
		# either :first or :all, to indicate that we want only one (:first) or
		# all (:all) results back from the resultant set.
		#
		# The second argument should be a hash of attribute_name => expected_value
		# pairs.
		#
		#   User.find(:all, :sn => 'Hunt')
		#
		# would find all of the User objects in Active Directory that have a
		# surname of exactly 'Hunt'.  as with the Base.exists? method, partial
		# searches are allowed.
		#
		# This method always returns an array if the caller specified :all for the
		# search type (first argument).  If no results are found, the array will
		# be empty.
		#
		# If you call find(:first, ...), you will either get an object (like a
		# User or a Group) back, or nil, if there were no entries matching your
		# filters.
		#
		def self.find(*args)
			options = {
				:filter => NIL_FILTER,
				:in => ''
			}
			options.merge!(args[1]) unless args[1].nil?
			options[:in] = [ options[:in].to_s, @@settings[:base] ].delete_if { |part| part.empty? }.join(",")
			if options[:filter].is_a? Hash
				options[:filter] = make_filter_from_hash(options[:filter])
			end
			options[:filter] = options[:filter] & filter unless self.filter == NIL_FILTER
			
			if (args.first == :all)
				find_all(options)
			elsif (args.first == :first)
				find_first(options)
			else
				raise ArgumentError, 'Invalid specifier (not :all, and not :first) passed to find()'
			end
		end

		def self.find_all(options)
			results = []
			@@ldap.search(:filter => options[:filter], :base => options[:in], :return_result => false) do |entry|
				results << new(entry)
			end
			results
		end

		def self.find_first(options)
			@@ldap.search(:filter => options[:filter], :base => options[:in], :return_result => false) do |entry|
				return new(entry)
			end
		end

		def self.method_missing(name, *args) # :nodoc:
			name = name.to_s
			if (name[0,5] == 'find_')
				find_spec, attribute_spec = parse_finder_spec(name)
				raise ArgumentError, "find: Wrong number of arguments (#{args.size} for #{attribute_spec.size})" unless args.size == attribute_spec.size
				filters = {}
				[attribute_spec,args].transpose.each { |pr| filters[pr[0]] = pr[1] }
				find(find_spec, :filter => filters)
			else
				super name.to_sym, args
			end
		end

		def self.parse_finder_spec(method_name) # :nodoc:
			# FIXME: This is a prime candidate for a
			# first-class object, FinderSpec

			method_name = method_name.gsub(/^find_/,'').gsub(/^by_/,'first_by_')
			find_spec, attribute_spec = *(method_name.split('_by_'))
			find_spec = find_spec.to_sym
			attribute_spec = attribute_spec.split('_and_').collect { |s| s.to_sym }

			return find_spec, attribute_spec
		end

		def ==(other) # :nodoc:
			return false if other.nil?
			other.distinguishedName == distinguishedName
		end

		#
		# Returns true if this entry does not yet exist in Active Directory.
		#
		def new_record?
			@entry.nil?
		end

		#
		# Refreshes the attributes for the entry with updated data from the
		# domain controller.
		#
		def reload
			return false if new_record?

			@entry = @@ldap.search(:filter => Net::LDAP::Filter.eq('distinguishedName',distinguishedName))[0]
			return !@entry.nil?
		end

		#
		# Updates a single attribute (name) with one or more values (value),
		# by immediately contacting the Active Directory server and initiating
		# the update remotely.
		#
		# Entries are always reloaded (via Base.reload) after calling this method.
		#
		def update_attribute(name, value)
			update_attributes(name.to_s => value)
		end

		#
		# Updates multiple attributes, like ActiveRecord#update_attributes.
		# The updates are immediately sent to the server for processing, and
		# the entry is reloaded after the update (if all went well).
		#
		def update_attributes(attributes_to_update)
			return true if attributes_to_update.empty?

			operations = []
			attributes_to_update.each do |attribute, values|
				if values.nil? || values.empty?
					operations << [ :delete, attribute, nil ]
				else
					values = [values] unless values.is_a? Array
					values = values.collect { |v| v.to_s }

					current_value = begin
						@entry.send(attribute)
					rescue NoMethodError
						nil
					end

					operations << [ (current_value.nil? ? :add : :replace), attribute, values ]
				end
			end

			@@ldap.modify(
				:dn => distinguishedName,
				:operations => operations
			) && reload
		end

		#
		# Create a new entry in the Active Record store.
		#
		# dn is the Distinguished Name for the new entry.	This must be
		# a unique identifier, and can be passed as either a Container object
		# or a plain string.
		#
		# attributes is a symbol-keyed hash of attribute_name => value pairs.
		#
		def self.create(dn,attributes)
			return nil if dn.nil? || attributes.nil?
			begin
				attributes.merge!(required_attributes)
				if @@ldap.add(:dn => dn.to_s, :attributes => attributes)
					return find_by_distinguishedName(dn.to_s)
				else
					return nil
				end
			rescue
				return nil
			end
		end

		#
		# Deletes the current entry from the Active Record store and returns true
		# if the operation was successfully.
		#
		def destroy
			return false if new_record?

			if @@ldap.delete(:dn => distinguishedName)
				@entry = nil
				@attributes = {}
				return true
			else
				return false
			end
		end

		#
		# Saves any pending changes to the entry by updating the remote entry.
		#
		def save
			if update_attributes(@attributes)
				@attributes = {}
				return true
			else
				return false
			end
		end

		#
		# This method may one day provide the ability to move entries from
		# container to container. Currently, it does nothing, as we are waiting
		# on the Net::LDAP folks to either document the Net::LDAP#modrdn method,
		# or provide a similar method for moving / renaming LDAP entries.
		#
		def move(new_rdn)
			return false if new_record?
			puts "Moving #{distinguishedName} to RDN: #{new_rdn}"

			settings = @@settings.dup
			settings[:port] = 636
			settings[:encryption] = { :method => :simple_tls }

			ldap = Net::LDAP.new(settings)

			if ldap.rename(
				:olddn => distinguishedName,
				:newrdn => new_rdn,
				:delete_attributes => false
			)
				return true
			else
				puts Base.error
				return false
			end
		end

		# FIXME: Need to document the Base::new
		def initialize(attributes = {}) # :nodoc:
			if attributes.is_a? Net::LDAP::Entry
				@entry = attributes
				@attributes = {}
			else
				@entry = nil
				@attributes = attributes
			end
		end

		def method_missing(name, args = []) # :nodoc:
			name_s = name.to_s.downcase
			name = name_s.to_sym
			if name_s[-1,1] == '='
				@attributes[name_s[0,name_s.size-1].to_sym] = args
			else
				if @attributes.has_key?(name)
					return @attributes[name]
				elsif @entry
					begin
						value = @entry.send(name)
						value = value.to_s if value.nil? || value.size == 1
						return value
					rescue NoMethodError
						return nil
					end
				else
					super
				end
			end
		end
	end
end
