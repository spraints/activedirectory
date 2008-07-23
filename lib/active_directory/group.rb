#--
# Ruby/ActiveDirectory : Active Directory Interface for Ruby
#
# Copyright (c) 2006-2008 James R. Hunt <james@niftylogic.net>
#++
module ActiveDirectory
	class Group < Base
		include Member

		def self.filter # :nodoc:
			Net::LDAP::Filter.eq(:objectClass,'group')
		end

		def self.required_attributes # :nodoc:
			{ :objectClass => [ 'top', 'group' ] }
		end

		def reload # :nodoc:
			@member_users_non_r  = nil
			@member_users_r      = nil
			@member_groups_non_r = nil
			@member_groups_r     = nil
			@groups              = nil
			super
		end

		#
		# Returns true if the passed User or Group object belongs to
		# this group. For performance reasons, the check is handled
		# by the User or Group object passed.
		#
		def has_member?(user)
			user.member_of?(self)
		end

		#
		# Add the passed User or Group object to this Group. Returns true if
		# the User or Group is already a member of the group, or if the operation
		# to add them succeeds.
		#
		def add(new_member)
			return false unless new_member.is_a?(User) || new_member.is_a?(Group)
			if @@ldap.modify(:dn => distinguishedName, :operations => [
				[ :add, :member, new_member.distinguishedName ]
			])
				return true
			else
				return has_member?(new_member)
			end
		end

		#
		# Remove a User or Group from this Group. Returns true if the User or
		# Group does not belong to this Group, or if the oepration to remove them
		# succeeds.
		#
		def remove(member)
			return false unless member.is_a?(User) || member.is_a?(Group)
			if @@ldap.modify(:dn => distinguishedName, :operations => [
				[ :delete, :member, member.distinguishedName ]
			])
				return true
			else
				return !has_member?(member)
			end
		end

		def has_members?
			begin
				return (@entry.member.nil? || @entry.member.empty?) ? false : true
			rescue NoMethodError
				return false
			end
		end

		#
		# Returns an array of all User objects that belong to this group.
		#
		# If the recursive argument is passed as false, then only Users who
		# belong explicitly to this Group are returned.
		#
		# If the recursive argument is passed as true, then all Users who
		# belong to this Group, or any of its subgroups, are returned.
		# 
		def member_users(recursive = false)
			return [] unless has_members?
			if recursive
				if @member_users_r.nil?
					@member_users_r = []
					@entry.member.each do |member_dn|
						subuser = User.find_by_distinguishedName(member_dn)
						if subuser
							@member_users_r << subuser
						else
							subgroup = Group.find_by_distinguishedName(member_dn)
							if subgroup
								@member_users_r = @member_users_r.concat(subgroup.member_users(true))
							end
						end
					end
				end
				return @member_users_r
			else
				@member_users_non_r ||= @entry.member.collect { |dn| User.find_by_distinguishedName(dn) }.delete_if { |u| u.nil? }
			end
		end

		#
		# Returns an array of all Group objects that belong to this group.
		#
		# If the recursive argument is passed as false, then only Groups that
		# belong explicitly to this Group are returned.
		#
		# If the recursive argument is passed as true, then all Groups that
		# belong to this Group, or any of its subgroups, are returned.
		# 
		def member_groups(recursive = false)
			return [] unless has_members?
			if recursive
				if @member_groups_r.nil?
					@member_groups_r = []
					@entry.member.each do |member_dn|
						subgroup = Group.find_by_distinguishedName(member_dn)
						if subgroup
							@member_groups_r << subgroup
							@member_groups_r = @member_groups_r.concat(subgroup.member_groups(true))
						end
					end
				end
				return @member_groups_r
			else
				@member_groups_non_r ||= @entry.member.collect { |dn| Group.find_by_distinguishedName(dn) }.delete_if { |g| g.nil? }
			end
		end

		#
		# Returns an array of Group objects that this Group belongs to.
		#
		def groups
			return [] if memberOf.nil?
			@groups ||= memberOf.collect { |group_dn| Group.find_by_distinguishedName(group_dn) }
		end
	end
end
