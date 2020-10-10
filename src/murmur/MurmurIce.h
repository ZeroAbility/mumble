// Copyright 2005-2020 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.
#ifndef MUMBLE_MURMUR_MURMURICE_H_
#   ifdef USE_ICE
#       define MUMBLE_MURMUR_MURMURICE_H_

#		include <QtCore/QtGlobal>

#		if defined(Q_OS_WIN) && !defined(WIN32_LEAN_AND_MEAN)
// To prevent <windows.h> (included by Ice) from including <winsock.h>.
#			define WIN32_LEAN_AND_MEAN
#		endif

#		include <QtCore/QList>
#		include <QtCore/QMap>
#		include <QtCore/QMutex>
#		include <QtCore/QObject>
#		include <QtCore/QWaitCondition>
#		include <QtNetwork/QSslCertificate>

#		include "MurmurI.h"

class Channel;
class Server;
class User;
struct TextMessage;

class MurmurIce : public QObject {
	friend class MurmurLocker;
	Q_OBJECT;

protected:
	int count;
	QMutex qmEvent;
	QWaitCondition qwcEvent;
#ifdef ICE_CPP11_MAPPING
    void customEvent(QEvent* evt);
    void badMetaProxy(const ::Murmur::MetaCallbackPrxPtr &prx);
    void badServerProxy(const ::Murmur::ServerCallbackPrxPtr &prx, ::std::shared_ptr<const ::Server> server);
	QList<::Murmur::MetaCallbackPrxPtr > qlMetaCallbacks;
	QMap< int, QList<::Murmur::ServerCallbackPrxPtr > > qmServerCallbacks;
	QMap< int, QMap< int, QMap< QString, ::Murmur::ServerContextCallbackPrxPtr > > > qmServerContextCallbacks;
	QMap< int, ::Murmur::ServerAuthenticatorPrxPtr > qmServerAuthenticator;
	QMap< int, ::Murmur::ServerUpdatingAuthenticatorPrxPtr > qmServerUpdatingAuthenticator;
    void badAuthenticator(::std::shared_ptr<::Server>);
#else
    void customEvent(QEvent *evt);
	void badMetaProxy(const ::Murmur::MetaCallbackPrx &prx);
	void badServerProxy(const ::Murmur::ServerCallbackPrx &prx, const ::Server *server);
	QList<::Murmur::MetaCallbackPrx > qlMetaCallbacks;
	QMap< int, QList<::Murmur::ServerCallbackPrx > > qmServerCallbacks;
	QMap< int, QMap< int, QMap< QString, ::Murmur::ServerContextCallbackPrx > > > qmServerContextCallbacks;
	QMap< int, ::Murmur::ServerAuthenticatorPrx > qmServerAuthenticator;
	QMap< int, ::Murmur::ServerUpdatingAuthenticatorPrx > qmServerUpdatingAuthenticator;
    void badAuthenticator(::Server *);
#endif



public:
	Ice::CommunicatorPtr communicator;
	Ice::ObjectAdapterPtr adapter;
	MurmurIce();
	~MurmurIce();

#ifdef ICE_CPP11_MAPPING
	void addMetaCallback(const ::Murmur::MetaCallbackPrxPtr &prx);
	void removeMetaCallback(const ::Murmur::MetaCallbackPrxPtr &prx);
	void addServerCallback(::std::shared_ptr<const ::Server> server, const ::Murmur::ServerCallbackPrxPtr &prx);
	void removeServerCallback(::std::shared_ptr<const ::Server> server, const ::Murmur::ServerCallbackPrxPtr &prx);
	void addServerContextCallback(::std::shared_ptr<const ::Server> server, int session_id, const QString &action,
								  const ::Murmur::ServerContextCallbackPrxPtr &prx);
	const QMap< int, QMap< QString, ::Murmur::ServerContextCallbackPrxPtr > >
		getServerContextCallbacks(::std::shared_ptr<const ::Server> server) const;
	void setServerAuthenticator(::std::shared_ptr<const ::Server> server, const ::Murmur::ServerAuthenticatorPrxPtr &prx);
	const Murmur::ServerAuthenticatorPrxPtr getServerAuthenticator(std::shared_ptr< const ::Server > server);
	void setServerUpdatingAuthenticator(::std::shared_ptr<const ::Server> server, const ::Murmur::ServerUpdatingAuthenticatorPrxPtr &prx);
	const ::Murmur::ServerUpdatingAuthenticatorPrxPtr getServerUpdatingAuthenticator(std::shared_ptr<const ::Server> server) const;
    void removeServerUpdatingAuthenticator(::std::shared_ptr<const ::Server> server);
	void removeServerCallbacks(::std::shared_ptr<const ::Server> server);
	void removeServerContextCallback(::std::shared_ptr<const ::Server> server, int session_id, const QString &action);
	void removeServerAuthenticator(::std::shared_ptr<const ::Server> server);
#else
	void addMetaCallback(const ::Murmur::MetaCallbackPrx &prx);
	void removeMetaCallback(const ::Murmur::MetaCallbackPrx &prx);
	void addServerCallback(const ::Server *server, const ::Murmur::ServerCallbackPrx &prx);
	void removeServerCallback(const ::Server *server, const ::Murmur::ServerCallbackPrx &prx);
	void addServerContextCallback(const ::Server *server, int session_id, const QString &action,
								  const ::Murmur::ServerContextCallbackPrx &prx);
	const QMap< int, QMap< QString, ::Murmur::ServerContextCallbackPrx > >
		getServerContextCallbacks(const ::Server *server) const;
	void setServerAuthenticator(const ::Server *server, const ::Murmur::ServerAuthenticatorPrx &prx);
	const ::Murmur::ServerAuthenticatorPrx getServerAuthenticator(const ::Server *server) const;
	void setServerUpdatingAuthenticator(const ::Server *server, const ::Murmur::ServerUpdatingAuthenticatorPrx &prx);
	const ::Murmur::ServerUpdatingAuthenticatorPrx getServerUpdatingAuthenticator(const ::Server *server) const;
    void removeServerUpdatingAuthenticator(const ::Server *server);
	void removeServerCallbacks(const ::Server *server);
	void removeServerContextCallback(const ::Server *server, int session_id, const QString &action);
	void removeServerAuthenticator(const ::Server *server);
#endif


public slots:
#ifdef ICE_CPP11_MAPPING
	void started(::std::shared_ptr<::Server>);
	void stopped(::std::shared_ptr<::Server>);
	void userConnected(::std::shared_ptr<const User> p);
	void userDisconnected(::std::shared_ptr<const User> p);
	void userStateChanged(::std::shared_ptr<const User> p);
	void userTextMessage(::std::shared_ptr<const User> p, const TextMessage &);
	void channelCreated(::std::shared_ptr<const Channel> c);
    void channelRemoved(::std::shared_ptr<const Channel> c);
    void channelStateChanged(::std::shared_ptr<const Channel> c);
    void contextAction(::std::shared_ptr<const ::User> , const QString &, unsigned int, int);
#else
	void started(Server *);
	void stopped(Server *);
	void userConnected(const User *p);
	void userDisconnected(const User *p);
	void userStateChanged(const User *p);
	void userTextMessage(const User *p, const TextMessage &);
	void channelCreated(const Channel *c);
    void channelRemoved(const Channel *c);
    void channelStateChanged(const Channel *c);
    void contextAction(const User *, const QString &, unsigned int, int);
#endif

	void authenticateSlot(int &res, QString &uname, int sessionId, const QList< QSslCertificate > &certlist,
						  const QString &certhash, bool certstrong, const QString &pw);
	void registerUserSlot(int &res, const QMap< int, QString > &);
	void unregisterUserSlot(int &res, int id);
	void getRegisteredUsersSlot(const QString &filter, QMap< int, QString > &res);
	void getRegistrationSlot(int &, int, QMap< Murmur::UserInfo, ::std::string > &);
	void setInfoSlot(int &, int, const QMap< int, QString > &);
	void setTextureSlot(int &res, int id, const QByteArray &texture);
	void nameToIdSlot(int &res, const QString &name);
	void idToNameSlot(QString &res, int id);
	void idToTextureSlot(QByteArray &res, int id);

};
#endif
#endif
