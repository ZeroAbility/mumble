// Copyright 2005-2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_MURMURI_H_
#define MUMBLE_MURMUR_MURMURI_H_

#include <Murmur.h>

namespace Murmur {
#ifdef ICE_CPP11_MAPPING // C++11 mapping
class ServerI : virtual public Server {
    virtual void isRunningAsync(::std::function<void (bool)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void startAsync(::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void stopAsync(::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void deleteAsync(::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void addCallbackAsync(::std::shared_ptr<ServerCallbackPrx> cb, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void removeCallbackAsync(::std::shared_ptr<ServerCallbackPrx> cb, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setAuthenticatorAsync(::std::shared_ptr<ServerAuthenticatorPrx> auth, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void idAsync(::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getConfAsync(::std::string key, ::std::function<void (const ::std::string &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getAllConfAsync(::std::function<void (const ConfigMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setConfAsync(::std::string key, ::std::string value, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setSuperuserPasswordAsync(::std::string pw, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getLogAsync(int first, int last, ::std::function<void (const LogList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getLogLenAsync(::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getUsersAsync(::std::function<void (const UserMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getChannelsAsync(::std::function<void (const ChannelMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getTreeAsync(::std::function<void (const ::std::shared_ptr<Tree> &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getCertificateListAsync(int session, ::std::function<void (const CertificateList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getBansAsync(::std::function<void (const BanList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setBansAsync(Murmur::BanList bans, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void kickUserAsync(int session, ::std::string reason, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void sendMessageAsync(int session, ::std::string text, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void hasPermissionAsync(int session, int channelid, int perm, ::std::function<void (bool)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void effectivePermissionsAsync(int session, int channelid, ::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void addContextCallbackAsync(int session, ::std::string action, ::std::string text, ::std::shared_ptr<ServerContextCallbackPrx> cb, int ctx, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void removeContextCallbackAsync(::std::shared_ptr<ServerContextCallbackPrx> cb, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getStateAsync(int session, ::std::function<void (const User &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setStateAsync(Murmur::User state, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getChannelStateAsync(int channelid, ::std::function<void (const Channel &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setChannelStateAsync(Murmur::Channel state, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void addChannelAsync(::std::string name, int parent, ::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void removeChannelAsync(int channelid, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void sendMessageChannelAsync(int channelid, bool tree, ::std::string text, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getACLAsync(int channelid, ::std::function<void (const ACLList &, const GroupList &, bool)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setACLAsync(int channelid, Murmur::ACLList acls, Murmur::GroupList groups, bool inherit, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void addUserToGroupAsync(int channelid, int session, ::std::string group, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void removeUserFromGroupAsync(int channelid, int session, ::std::string group, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void redirectWhisperGroupAsync(int session, ::std::string source, ::std::string target, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getUserIdsAsync(Murmur::NameList names, ::std::function<void (const IdMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getUserNamesAsync(Murmur::IdList ids, ::std::function<void (const NameMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void registerUserAsync(Murmur::UserInfoMap info, ::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void unregisterUserAsync(int userid, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getRegistrationAsync(int userid, ::std::function<void (const UserInfoMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void updateRegistrationAsync(int userid, Murmur::UserInfoMap info, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getRegisteredUsersAsync(::std::string filter, ::std::function<void (const NameMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void verifyPasswordAsync(::std::string name, ::std::string pw, ::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getTextureAsync(int userid, ::std::function<void (const Texture &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void setTextureAsync(int userid, Murmur::Texture tex, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getUptimeAsync(::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void updateCertificateAsync(::std::string certificate, ::std::string privateKey, ::std::string passphrase, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void startListeningAsync(int userid, int channelid, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void stopListeningAsync(int userid, int channelid, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void isListeningAsync(int userid, int channelid, ::std::function<void (bool)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getListeningChannelsAsync(int userid, ::std::function<void (const IntList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getListeningUsersAsync(int channelid, ::std::function<void (const IntList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void ice_ping(const Ice::Current & current) const;
};

class MetaI : public Meta {
    virtual void getSliceChecksumsAsync(::std::function<void (const ::Ice::SliceChecksumDict &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getServerAsync(int id, ::std::function<void (const ::std::shared_ptr<ServerPrx> &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void newServerAsync(::std::function<void (const ::std::shared_ptr<ServerPrx> &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getBootedServersAsync(::std::function<void (const ServerList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getAllServersAsync(::std::function<void (const ServerList &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getDefaultConfAsync(::std::function<void (const ConfigMap &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getVersionAsync(::std::function<void (int, int, int, const ::std::string &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void addCallbackAsync(::std::shared_ptr<MetaCallbackPrx> cb, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void removeCallbackAsync(::std::shared_ptr<MetaCallbackPrx> cb, ::std::function<void ()> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getUptimeAsync(::std::function<void (int)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
    
    virtual void getSliceAsync(::std::function<void (const ::std::string &)> response, ::std::function<void (::std::exception_ptr)> exception, const ::Ice::Current & current);
};

#else // C++98 mapping
class ServerI : virtual public Server {
public:
	virtual void isRunning_async(const ::Murmur::AMD_Server_isRunningPtr &, const Ice::Current &);

	virtual void start_async(const ::Murmur::AMD_Server_startPtr &, const Ice::Current &);

	virtual void stop_async(const ::Murmur::AMD_Server_stopPtr &, const Ice::Current &);

	virtual void delete_async(const ::Murmur::AMD_Server_deletePtr &, const Ice::Current &);

	virtual void addCallback_async(const ::Murmur::AMD_Server_addCallbackPtr &, const ::Murmur::ServerCallbackPrx &,
								   const ::Ice::Current &);
	virtual void removeCallback_async(const ::Murmur::AMD_Server_removeCallbackPtr &,
									  const ::Murmur::ServerCallbackPrx &, const ::Ice::Current &);

	virtual void setAuthenticator_async(const ::Murmur::AMD_Server_setAuthenticatorPtr &,
										const ::Murmur::ServerAuthenticatorPrx &, const ::Ice::Current &);

	virtual void id_async(const ::Murmur::AMD_Server_idPtr &, const Ice::Current &);

	virtual void getConf_async(const ::Murmur::AMD_Server_getConfPtr &, const ::std::string &, const Ice::Current &);

	virtual void getAllConf_async(const ::Murmur::AMD_Server_getAllConfPtr &, const Ice::Current &);

	virtual void setConf_async(const ::Murmur::AMD_Server_setConfPtr &, const ::std::string &, const ::std::string &,
							   const Ice::Current &);

	virtual void setSuperuserPassword_async(const ::Murmur::AMD_Server_setSuperuserPasswordPtr &, const ::std::string &,
											const Ice::Current &);

	virtual void getLog_async(const ::Murmur::AMD_Server_getLogPtr &, ::Ice::Int, ::Ice::Int, const Ice::Current &);

	virtual void getLogLen_async(const ::Murmur::AMD_Server_getLogLenPtr &, const Ice::Current &);

	virtual void getUsers_async(const ::Murmur::AMD_Server_getUsersPtr &, const Ice::Current &);

	virtual void getChannels_async(const ::Murmur::AMD_Server_getChannelsPtr &, const Ice::Current &);

	virtual void getTree_async(const ::Murmur::AMD_Server_getTreePtr &, const Ice::Current &);

	virtual void getCertificateList_async(const ::Murmur::AMD_Server_getCertificateListPtr &, ::Ice::Int,
										  const ::Ice::Current &);

	virtual void getBans_async(const ::Murmur::AMD_Server_getBansPtr &, const Ice::Current &);

	virtual void setBans_async(const ::Murmur::AMD_Server_setBansPtr &, const ::Murmur::BanList &,
							   const Ice::Current &);

	virtual void kickUser_async(const ::Murmur::AMD_Server_kickUserPtr &, ::Ice::Int, const ::std::string &,
								const Ice::Current &);

	virtual void sendMessage_async(const ::Murmur::AMD_Server_sendMessagePtr &, ::Ice::Int, const ::std::string &,
								   const Ice::Current &);

	virtual void hasPermission_async(const ::Murmur::AMD_Server_hasPermissionPtr &, ::Ice::Int, ::Ice::Int, ::Ice::Int,
									 const ::Ice::Current &);
	virtual void effectivePermissions_async(const ::Murmur::AMD_Server_effectivePermissionsPtr &, ::Ice::Int,
											::Ice::Int, const ::Ice::Current &);

	virtual void addContextCallback_async(const ::Murmur::AMD_Server_addContextCallbackPtr &, ::Ice::Int,
										  const ::std::string &, const ::std::string &,
										  const ::Murmur::ServerContextCallbackPrx &, int, const ::Ice::Current &);
	virtual void removeContextCallback_async(const ::Murmur::AMD_Server_removeContextCallbackPtr &,
											 const ::Murmur::ServerContextCallbackPrx &, const ::Ice::Current &);

	virtual void getState_async(const ::Murmur::AMD_Server_getStatePtr &, ::Ice::Int, const Ice::Current &);

	virtual void setState_async(const ::Murmur::AMD_Server_setStatePtr &, const ::Murmur::User &, const Ice::Current &);

	virtual void getChannelState_async(const ::Murmur::AMD_Server_getChannelStatePtr &, ::Ice::Int,
									   const Ice::Current &);

	virtual void setChannelState_async(const ::Murmur::AMD_Server_setChannelStatePtr &, const ::Murmur::Channel &,
									   const Ice::Current &);

	virtual void removeChannel_async(const ::Murmur::AMD_Server_removeChannelPtr &, ::Ice::Int, const Ice::Current &);

	virtual void addChannel_async(const ::Murmur::AMD_Server_addChannelPtr &, const ::std::string &, ::Ice::Int,
								  const Ice::Current &);

	virtual void sendMessageChannel_async(const ::Murmur::AMD_Server_sendMessageChannelPtr &, ::Ice::Int, bool,
										  const ::std::string &, const Ice::Current &);

	virtual void getACL_async(const ::Murmur::AMD_Server_getACLPtr &, ::Ice::Int, const Ice::Current &);

	virtual void setACL_async(const ::Murmur::AMD_Server_setACLPtr &, ::Ice::Int, const ::Murmur::ACLList &,
							  const ::Murmur::GroupList &, bool, const Ice::Current &);

	virtual void removeUserFromGroup_async(const ::Murmur::AMD_Server_removeUserFromGroupPtr &, ::Ice::Int, ::Ice::Int,
										   const ::std::string &, const ::Ice::Current &);

	virtual void addUserToGroup_async(const ::Murmur::AMD_Server_addUserToGroupPtr &, ::Ice::Int, ::Ice::Int,
									  const ::std::string &, const ::Ice::Current &);

	virtual void redirectWhisperGroup_async(const ::Murmur::AMD_Server_redirectWhisperGroupPtr &, ::Ice::Int,
											const ::std::string &, const ::std::string &, const ::Ice::Current &);

	virtual void getUserNames_async(const ::Murmur::AMD_Server_getUserNamesPtr &, const ::Murmur::IdList &,
									const Ice::Current &);

	virtual void getUserIds_async(const ::Murmur::AMD_Server_getUserIdsPtr &, const ::Murmur::NameList &,
								  const Ice::Current &);

	virtual void registerUser_async(const ::Murmur::AMD_Server_registerUserPtr &, const Murmur::UserInfoMap &,
									const Ice::Current &);

	virtual void unregisterUser_async(const ::Murmur::AMD_Server_unregisterUserPtr &, ::Ice::Int, const Ice::Current &);

	virtual void updateRegistration_async(const ::Murmur::AMD_Server_updateRegistrationPtr &, Ice::Int,
										  const Murmur::UserInfoMap &, const Ice::Current &);

	virtual void getRegistration_async(const ::Murmur::AMD_Server_getRegistrationPtr &, ::Ice::Int,
									   const Ice::Current &);

	virtual void getRegisteredUsers_async(const ::Murmur::AMD_Server_getRegisteredUsersPtr &, const ::std::string &,
										  const Ice::Current &);

	virtual void verifyPassword_async(const ::Murmur::AMD_Server_verifyPasswordPtr &, const ::std::string &,
									  const ::std::string &, const Ice::Current &);

	virtual void getTexture_async(const ::Murmur::AMD_Server_getTexturePtr &, ::Ice::Int, const Ice::Current &);

	virtual void setTexture_async(const ::Murmur::AMD_Server_setTexturePtr &, ::Ice::Int, const ::Murmur::Texture &,
								  const Ice::Current &);

	virtual void getUptime_async(const ::Murmur::AMD_Server_getUptimePtr &, const Ice::Current &);

	virtual void updateCertificate_async(const ::Murmur::AMD_Server_updateCertificatePtr &, const std::string &,
										 const std::string &, const std::string &, const Ice::Current &);

	virtual void startListening_async(const ::Murmur::AMD_Server_startListeningPtr &, ::Ice::Int, ::Ice::Int,
									  const Ice::Current &);

	virtual void stopListening_async(const ::Murmur::AMD_Server_stopListeningPtr &, ::Ice::Int, ::Ice::Int,
									 const Ice::Current &);

	virtual void isListening_async(const ::Murmur::AMD_Server_isListeningPtr &, ::Ice::Int, ::Ice::Int,
								   const Ice::Current &);

	virtual void getListeningChannels_async(const ::Murmur::AMD_Server_getListeningChannelsPtr &, ::Ice::Int,
											const Ice::Current &);

	virtual void getListeningUsers_async(const ::Murmur::AMD_Server_getListeningUsersPtr &, ::Ice::Int,
										 const Ice::Current &);

	virtual void ice_ping(const Ice::Current &) const;
};

class MetaI : virtual public Meta {
public:
	virtual void getSliceChecksums_async(const ::Murmur::AMD_Meta_getSliceChecksumsPtr &, const ::Ice::Current &);

	virtual void getServer_async(const ::Murmur::AMD_Meta_getServerPtr &, ::Ice::Int, const Ice::Current &);

	virtual void newServer_async(const ::Murmur::AMD_Meta_newServerPtr &, const Ice::Current &);

	virtual void getBootedServers_async(const ::Murmur::AMD_Meta_getBootedServersPtr &, const Ice::Current &);

	virtual void getAllServers_async(const ::Murmur::AMD_Meta_getAllServersPtr &, const Ice::Current &);

	virtual void getDefaultConf_async(const ::Murmur::AMD_Meta_getDefaultConfPtr &, const Ice::Current &);

	virtual void getVersion_async(const ::Murmur::AMD_Meta_getVersionPtr &, const Ice::Current &);


	virtual void addCallback_async(const ::Murmur::AMD_Meta_addCallbackPtr &, const ::Murmur::MetaCallbackPrx &,
								   const ::Ice::Current & = ::Ice::Current());
	virtual void removeCallback_async(const ::Murmur::AMD_Meta_removeCallbackPtr &, const ::Murmur::MetaCallbackPrx &,
									  const ::Ice::Current & = ::Ice::Current());

	virtual void getUptime_async(const ::Murmur::AMD_Meta_getUptimePtr &, const Ice::Current &);

	virtual void getSlice_async(const ::Murmur::AMD_Meta_getSlicePtr &, const Ice::Current &);
};

#endif
} // namespace Murmur
#endif
