# UserSynchronizer is a utility class that encapsulates dealings
# with the Active Directory backend. It is primarily responsible for
# updating Active Directory people in the local database from the
# Active Directory store. In this fashion, name changes, email address
# changes and such are all handled invisibly.
#
# UserSynchronizer is also responsible for disabling people who are no
# longer in the Sales Tracker group, and creating people who are in the group,
# but not in the local database. This gives us another administrative
# convenience, since new hires will be added to the system with some
# regularity, and terminations are eventually cleaned out.
#
# UserSynchronizer.sync_users_in_group will return a hash with the following keys:
#   * :added - An array of ActiveDirectory::User objects that were added.
#   * :disabled - An array of ActiveDirectory::User objects that were disabled.
#   * :updated - An array of ActiveDirectory::User objects that were updated.
#
# The following method illustrates how this would be used to notify a site
# administrator to changes brought about by synchronization:
#
#   def report(results)
#     puts "#####################################################"
#     puts "#  Active Directory People Synchronization Summary  #"
#     puts "#####################################################"
#     puts
#
#     puts "New People Added (#{results[:added].size})"
#     puts "-----------------------------------------------------"
#     results[:added].sort_by(&:name).each { |p| out.puts " + #{p.name}" }
#     puts
#
#     puts "People Disabled (#{results[:disabled].size})"
#     puts "-----------------------------------------------------"
#     results[:disabled].sort_by(&:name).each { |p| out.puts " - #{p.name}" }
#     puts
#
#     puts "Existing People Updated (#{results[:updated].size})"
#     puts "-----------------------------------------------------"
#     results[:updated].sort_by(&:name).each { |p| out.puts " u #{p.name}" }
#     puts
#   end
#
class ActiveDirectory::Rails::UserSynchronizer
	@@default_group = nil
	cattr_accessor :default_group

	@@run_handler = nil
	cattr_accessor :run_handler

	@@attribute_map = {
		:first_name => :givenName,
		:last_name  => :sn,
		:username   => :sAMAccountName,
		:email      => :mail,
	}
	cattr_accessor :attribute_map

	@@person_class = Person
	cattr_accessor :person_class

	class << self
		# The primary interface to synchronization, run processes
		# all of the Active Directory changes, additions and removals
		# through sync_users_in_group, and then notifies administrators
		# if it finds anyone new.
		#
		# This is the preferred way to run the UserSynchronizer.
		#
		def run
			results = sync_users_in_group
			@@run_handler.nil? results : @@run_handler.call(results)
		end

		# Compares the membership of the Active Directory group named
		# `group_name' and AD-enabled accounts in the local database.
		#
		# This method is the workhorse of UserSynchronizer, handling
		# the addition, removal and updates of AD people.
		#
		# It will return either false, or a hash with three keys, :added, :updated
		# and :disabled, each of which contains an array of the Person
		# objects that were (respectively) added, updated and disabled.
		#
		# If the given group_name does not resolve to a valid
		# ActiveDirectory::Group object, sync_users_in_group will return
		# false.
		#
		# The return value (for example) can be used by a notification process
		# to construct a message detailing who was added, removed, etc.
		#
		def sync_users_in_group(group_name = nil)
			group_name ||= @@default_group
			return false unless group_name

			ad_group = ActiveDirectory::Group.find_by_sAMAccountName(group_name)
			return false unless ad_group

			@people = person_class.in_active_directory.index_by(&:guid)

			summary = {
				:added    => [],
				:disabled => [],
				:updated  => []
			}

			# Find all member users (recursively looking at member groups)
			# and synchronize! them with their Person counterparts.
			#
			ad_group.member_users(true).each do |ad_user|
				person = @people[ad_user.objectGUID]
				if person
					synchronize!(person, ad_user)
					@people.delete(ad_user.objectGUID)
					summary[:updated] << person
				else
					person = create_from(ad_user)
					summary[:added] << person
				end
			end

			# Disable AD users we didn't find in AD.
			# Because we are not clearing the GUID in the disable! call,
			# we may process someone more than once.
			#
			@people.each do |guid, person|
				disable!(person)
				summary[:disabled] << person
			end

			summary
		end

		# Synchronize a peron with AD store by looking up their username.
		#
		# This is used for the initial bootstrap, because we don't know
		# a person's objectGUID offhand. It will probably never be seen
		# in any production code.
		#
		def update_using_username(person)
			ad_user = ActiveDirectory::User.find_by_sAMAccountName(person.username)
			synchronize!(person, ad_user)
		end

		# Sync a person with AD store by looking up their GUID
		# (This is the most reliable option, as a username can change,
		# but the GUID will stay the same).
		#
		# This method is not used in production, but can be useful in
		# a console'd environment to selectively update just a few people.
		#
		def update_using_guid(person)
			ad_user = ActiveDirectory::User.find_by_objectGUID(person.guid)
			synchronize!(person, ad_user)
		end

		# Synchronize the attributes of the given Person with those
		# found in the (hopefully associated) Active Directory user
		#
		# Because we are managing a mixed database of both AD and non-AD
		# people, we have to be careful. We cannot assume that a nil
		# ad_user argument means the person should be disabled.
		#
		def synchronize!(person, ad_user)
			person.update_attributes(attributes_from(ad_user)) if ad_user
		end

		# Disable a person, and clear out their authentication information.
		# This is primarily used when we find terminated employees who are
		# still in the local database as AD users, but no longer have an
		# AD account.
		#
		# There is a special case for people who have not logged sales.
		# They are removed outright, to keep terminated trainees from
		# cluttering up the Person table.
		#
		# Note that we do not clear their GUID. Active Directory is not
		# supposed to re-use its GUIDs, so we should be safe there.
		#
		def disable!(person)
			if person.respond_to? :removable? and !person.removable?
				person.update_attribute(:username, '')
				person.update_attribute(:email,    '')
			else
				person.destroy
			end
		end

		# Creates a new Person object based on the attributes of
		# an Active Directory user. sync_users_in_group uses this when
		# it finds new people.
		#
		# All Person objects will be created as generic Persons,
		# not CSRs or TeamLeaders. Administrators are responsible
		# for promoting and associating new people in the backend.
		#
		def create_from(ad_user)
			person = person_class.create(attributes_from(ad_user))
		end

		# Translates the attributes of ad_user into a hash that can
		# be used to create or update a Person object.
		#
		def attributes_from(ad_user)
			h = {}
			@@attribute_map.each { |local, remote| h[local] = ad_user.send(remote) }
			h[:guid] = ad_user.objectGUID
			h[:password => '']
			h
		end
	end
end
