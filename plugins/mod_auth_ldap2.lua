-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.
--
-- As per the sublicensing clause, this file is also MIT/X11 Licensed.
-- ** Copyright (c) 2010-2013, Kim Alvefur, Matthew Wild, Tobias Markmann, Waqas Hussain

-- local datamanager = require "util.datamanager";
-- local log = require "util.logger".init("auth_internal_hashed");
-- local getAuthenticationDatabaseSHA1 = require "util.sasl.scram".getAuthenticationDatabaseSHA1;
-- local generate_uuid = require "util.uuid".generate;
-- local new_sasl = require "util.sasl".new;
-- local plain_test = module:require "sasl_aux".hashed_plain_test;
-- local scram_backend = module:require "sasl_aux".hashed_scram_backend;
-- local external_backend = module:require "sasl_aux".external_backend;
-- local from_hex = module:require "sasl_aux".from_hex;
-- local to_hex = module:require "sasl_aux".to_hex;

local ldap     = module:require 'ldap';
local new_sasl = require 'util.sasl'.new;
local jsplit   = require 'util.jid'.split;

if not ldap then
    log("info", "Could not load LDAP lib");
    return;
end

function new_hashpass_provider(host)
	local provider = { name = "ldap2" };
	log("debug", "initializing LDAP authentication provider for host '%s'", host);

	function provider.test_password(username, password)
	    log("debug", "Testing password for user '%s'", username);
	    return ldap.bind(username, password);
	end

	function provider.user_exists(username)
	    log("debug", "Testing user existance for user '%s'", username);
	    local params = ldap.getparams()

	    local filter = ldap.filter.combine_and(params.user.filter, params.user.usernamefield .. '=' .. username);
	    if params.user.usernamefield == 'mail' then
		filter = ldap.filter.combine_and(params.user.filter, 'mail=' .. username .. '@*');
	    end

	    return ldap.singlematch {
		base   = params.user.basedn,
		filter = filter,
	    };
	end

	function provider.get_password(username)
	    return nil, "Passwords unavailable for LDAP.";
	end

	function provider.set_password(username, password)
	    return nil, "Passwords unavailable for LDAP.";
	end

	function provider.create_user(username, password)
	    return nil, "Account creation/modification not available with LDAP.";
	end

	function provider.get_sasl_handler()
	    log("debug", "Getting SASL handler");
	    local testpass_authentication_profile = {
		plain_test = function(sasl, username, password, realm)
		    return provider.test_password(username, password), true;
		end,
		mechanisms = { PLAIN = true },
	    };
	    return new_sasl(module.host, testpass_authentication_profile);
	end

	function provider.is_admin(jid)
	    local admin_config = ldap.getparams().admin;

	    if not admin_config then
		return;
	    end

	    local ld       = ldap:getconnection();
	    local username = jsplit(jid);
	    local filter   = ldap.filter.combine_and(admin_config.filter, admin_config.namefield .. '=' .. username);

	    return ldap.singlematch {
		base   = admin_config.basedn,
		filter = filter,
	    };
	end
	
	return provider;
end

module:add_item("auth-provider", new_hashpass_provider(module.host));
