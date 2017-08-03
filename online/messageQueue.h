#include <activemq/util/Config.h>
#include <decaf/lang/System.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/library/ActiveMQCPP.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/Destination.h>
#include <cms/MessageProducer.h>
#include <cms/BytesMessage.h>
#include <cms/CMSException.h>

#include <string>
#include <iostream>


using namespace cms;
using namespace activemq;
using namespace activemq::core;
using namespace decaf;
using namespace decaf::lang;
using namespace std;

class MessageQueue{
public:
	std::auto_ptr<MessageProducer> producer;
	std::auto_ptr<BytesMessage> message;
	std::auto_ptr<Session> session;
	auto_ptr<Connection> connection;

	MessageQueue();
};

string getEnv(const string& key, const string& defaultValue);
string getArg(char* argv[], int argc, int index, const string& defaultValue);