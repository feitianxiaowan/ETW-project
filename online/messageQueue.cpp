#include "messageQueue.h"

using namespace cms;
using namespace activemq;
using namespace activemq::core;
using namespace decaf;
using namespace decaf::lang;

using namespace std;


MessageQueue::MessageQueue(){
	activemq::library::ActiveMQCPP::initializeLibrary();

	cout << "=====================================================\n";
	cout << "Starting the Publisher :" << std::endl;
	cout << "-----------------------------------------------------\n";

	string user = getEnv("ACTIVEMQ_USER", "admin");
	string password = getEnv("ACTIVEMQ_PASSWORD", "admin");
	string host = getEnv("ACTIVEMQ_HOST", "10.214.148.122");
	int port = Integer::parseInt(getEnv("ACTIVEMQ_PORT", "61616"));
	string destination = getArg(NULL, 0, 1, "new");

	ActiveMQConnectionFactory factory;
	factory.setBrokerURI(std::string("tcp://") + host + ":" + Integer::toString(port));

	auto_ptr<Connection> tempconnection(factory.createConnection(user, password));
	tempconnection->start();
	printf("connection\n");
	auto_ptr<Session> tempsession(tempconnection->createSession());
	printf("Session\n");
	auto_ptr<Destination> tempdest(tempsession->createTopic(destination));
	auto_ptr<MessageProducer> tempproducer(tempsession->createProducer(tempdest.get()));

	connection = tempconnection;
	session = tempsession;
	producer = tempproducer;



	producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
	cout << "Initialized." << endl;
}


string getEnv(const string& key, const string& defaultValue) {

	try{
		return System::getenv(key);
	}
	catch (...) {
	}

	return defaultValue;
}

//////////////////////////////////////////////////////////////////////////////
string getArg(char* argv[], int argc, int index, const string& defaultValue) {

	if (index < argc) {
		return argv[index];
	}

	return defaultValue;
}
