#-- license
#
# This file is part of the Ruby Active Directory Project
# on the web at http://rubyforge.org/projects/activedirectory
#
#  Copyright (c) 2008, James Hunt <filefrog@gmail.com>
#    based on original code by Justin Mecham
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#++ license

module ActiveDirectory::Rails::User
	def self.included(klass)
		klass.extend(ClassMethods)
		klass.send(:include, InstanceMethods)
	end
	
	module InstanceMethods
		# Is this Person active? Active people have valid
		# usernames. Inactive people have empty usernames.
		#
		def active?
			username != ""
		end

		# Whether or not this Person has a corresponding Active Directory
		# account that we can synchronize with, through the PeopleSynchronizer.
		#
		def in_active_directory?
			!guid.blank?
		end

		# Whether or not this Person can be authenticated with the
		# given password, against Active Directory.
		#
		# For Active Directory authentication, we attempt to bind to the
		# configured AD server as the user, and supply the password for
		# authentication.
		#
		# There are two special cases for authentication, related to the
		# environment the app is currently running in:
		#
		# *Development*
		#
		# In development, the blank password ('') will always cause this method
		# to return true, thereby allowing developers to test functionality
		# for a variety of roles.
		#
		# *Training*
		#
		# In training, a special training password ('trainme') will always
		# cause this method to return true, thereby allowing trainers to
		# use other people accounts to illustrate certain restricted processes.
		#
		def authenticates?(password)
			# Never allow inactive users.
			return false unless active?
	
			# Allow blank password for any account in development.
			return true if password == "" and ENV['RAILS_ENV'] == 'development'
			return true if password == "trainme" and ENV['RAILS_ENV'] == 'training'

			# Don't go against AD unless we really mean it.
			return false unless ENV['RAILS_ENV'] == 'production'

			# If they are not in AD, fail.
			return false unless in_active_directory?
	
			ad_user = ActiveDirectory::User.find_by_sAMAccountName(self.username)
			ad_user and ad_user.authenticate(password)
		end

		def active_directory_equivalent=(ad_user)
			return unless ad_user
			update_attributes(
				:first_name  => ad_user.givenName,
				:middle_name => ad_user.initials,
				:last_name   => ad_user.sn,
				:username    => ad_user.sAMAccountName,
				:email       => ad_user.mail,
				:guid        => ad_user.objectGUID
			)
		end
	end

	module ClassMethods
		# Attempt to authenticate someone with a username and password.
		# This method properly handles both local store users and AD
		# users.
		#
		# If the username is valid, and the password matches the username,
		# the Person object corresponding to the username is return.
		# 
		# Otherwise, nil is returned, to indicate an authentication failure.
		#
		def authenticate(username, password)
			person = find_by_username(username)
			return person if (person and person.authenticates?(password))
			nil
		end

		# Retrieves all of the Person objects that have corresponding
		# Active Directory accounts. This method does not contact
		# the AD servers to retrieve the AD objects -- that is left up
		# to the caller.
		#
		def in_active_directory
			find(:all, :conditions => 'guid IS NOT NULL AND guid != ""')
		end

		# Retrieves all Person objects that are currently active,
		# meaning they have not been disabled by PeopleSynchronizer.
		#
		def active
			find(:all, :conditions => 'username != ""')
		end

		# Retrieves all Person objects that are currently inactive,
		# meaning they have been disabled by PeopleSynchronizer.
		#
		def inactive
			find(:all, :conditions => 'username = ""')
		end
	end
end 
