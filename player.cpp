#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <string>

#define PARAMETERS 7
#define UDP_BUFFER_SIZE 100
#define TCP_BUFFER_SIZE 100000
#define HEADER_BUFFER_SIZE 1000
#define MAX_METADATA_SIZE 4080
#define HTTP_REQUEST_LENGTH 1000

// Parameters of program	
char* host;
char* path;
char* r_port;
char* file;
char* m_port;
bool md;
int metaint;

// Variables necesary for UDP/TCP connection
int sockTCP;
int sockUDP;
struct addrinfo addr_hints;
struct addrinfo *addr_result;
struct sockaddr_in server_address;
struct sockaddr_in client_address;
socklen_t rcva_len;
socklen_t snda_len;
int flags;
char udp_buffer[UDP_BUFFER_SIZE];
char tcp_buffer[TCP_BUFFER_SIZE];
char header_buffer[HEADER_BUFFER_SIZE+1];
char http_request[HTTP_REQUEST_LENGTH];

// Variables for thread management
pthread_t TCPthread;
pthread_t UDPthread;
pthread_mutex_t mutex;

std::ostream* output = &std::cout;

// Flow controling variables
int play = 1;
int end_program = 0;
std::string title = "";

void syserr(std::string message){
	std::cerr << message << std::endl;
	throw 1;
}

void set_new_title(std::string metadate){
	if(metadate.length() > 0){
		int start = metadate.find("StreamTitle='");
		if(start == std::string::npos){
			syserr("Wrong metadata provided");
		}
		start += std::string("StreamTitle='").length();
		metadate = metadate.substr(start);
		int end = metadate.find("'");
		metadate = metadate.substr(0,end);
		pthread_mutex_lock(&mutex);
		title = metadate;
		pthread_mutex_unlock(&mutex);
	}
}

void* runUDP(void* arg){
	while(!end_program){
		int len;
		memset(&(udp_buffer[0]), 0, sizeof(udp_buffer));
		rcva_len = (socklen_t) sizeof(client_address);
		snda_len = (socklen_t) sizeof(client_address);
		flags = 0;
		len = recvfrom(sockUDP, udp_buffer, sizeof(udp_buffer), flags,
				(struct sockaddr *) &client_address, &rcva_len);
		if(strcmp(udp_buffer,"PAUSE") == 0){
			pthread_mutex_lock(&mutex);
			play = 0;
			printf("PAUSE\n");
			pthread_mutex_unlock(&mutex);
			printf("po pause\n");
		} else if(strcmp(udp_buffer,"PLAY") == 0){
			pthread_mutex_lock(&mutex);
			play = 1;
			printf("PLAY\n");
			pthread_mutex_unlock(&mutex);
		} else if(strcmp(udp_buffer,"TITLE") == 0){
			pthread_mutex_lock(&mutex);
			std::string temp_title = title;
			printf("TITLE\n");
			pthread_mutex_unlock(&mutex);
			sendto(sockUDP, temp_title.c_str(), (size_t) temp_title.length(), flags, (struct sockaddr *) &client_address, snda_len);
		} else if(strcmp(udp_buffer,"QUIT") == 0){
			pthread_mutex_lock(&mutex);
			if(!end_program) end_program = 1;
			printf("QUIT\n");
			pthread_mutex_unlock(&mutex);
		}

	}
	return NULL;
}

void* runTCPwithoutmetadate(void* arg){
	write(sockTCP, http_request, strlen(http_request));
	int pos;
	int len;
	std::string loaded_buffer = "";
	while(loaded_buffer.find("\r\n\r\n") == std::string::npos){
		len = read(sockTCP, &(header_buffer), HEADER_BUFFER_SIZE);
		if(len == 0) syserr("server ended connection");
		header_buffer[len] = 0;
		loaded_buffer += std::string(header_buffer,len);
	}
	pos = loaded_buffer.find("\r\n\r\n");
	std::string header = loaded_buffer.substr(0,pos);
	std::string message = loaded_buffer.substr(pos+4);
	output -> write(message.c_str(), message.length());

	while(!end_program){
		pthread_mutex_lock(&mutex);
		if(play){
			pthread_mutex_unlock(&mutex);
			len = read(sockTCP, &(tcp_buffer[0]), TCP_BUFFER_SIZE - 1);
			if(len == 0) exit(0);	
			tcp_buffer[len] = 0;
			message = std::string(tcp_buffer, len);
			output -> write(message.c_str(), message.length());
		} else {
			pthread_mutex_unlock(&mutex);
		}

	}

}

void* runTCPwithmetadate(void* arg){
	write(sockTCP, http_request, strlen(http_request));
	int buffer_left = HEADER_BUFFER_SIZE;
	int len = 0;
	int metaint_counter = 0;
	int pos;
	std::string loaded_buffer = "";
	while(loaded_buffer.find("\r\n\r\n") == std::string::npos){
		len = read(sockTCP, &(header_buffer), HEADER_BUFFER_SIZE);
		if(len == 0) syserr("server ended connection");
		header_buffer[len] = 0;
		loaded_buffer += std::string(header_buffer,len);
	}
	pos = loaded_buffer.find("\r\n\r\n");
	if(pos == std::string::npos) syserr("Wrong metadata given");
	std::string header = loaded_buffer.substr(0,pos);
	std::string rest_of_message = loaded_buffer.substr(pos+4);

	// Geting value of metaint
	pos = header.find("icy-metaint:");
	header = header.substr(pos + std::string("icy-metaint:").length());
	pos = header.find("\r\n");
	header = header.substr(0,pos);
	metaint = std::stoi(header);


	while(!end_program){
		pthread_mutex_lock(&mutex);
		if(play){
			pthread_mutex_unlock(&mutex);
			if(rest_of_message.length() < metaint + MAX_METADATA_SIZE + 1){
				int len = read(sockTCP, &(tcp_buffer[0]), TCP_BUFFER_SIZE-1);
				if(len == 0) exit(0);		
				tcp_buffer[len] = 0;
				rest_of_message += std::string(tcp_buffer, len);
			}
			if(metaint_counter + rest_of_message.length() < metaint){
				output -> write(rest_of_message.c_str(), rest_of_message.length());
				metaint_counter += rest_of_message.length();
				rest_of_message = "";
			} else {
				int how_many = metaint - metaint_counter;
				std::string message = rest_of_message.substr(0,how_many);
				output -> write(message.c_str(), message.length());
				rest_of_message = rest_of_message.substr(how_many);
				metaint_counter = 0;
				if(rest_of_message.length() == 0){
					int len = read(sockTCP, &(tcp_buffer[0]), 1);
					if(len == 0) exit(0);		
					tcp_buffer[len] = 0;
					rest_of_message += std::string(tcp_buffer,len);
				}
				unsigned char meta_char_length = rest_of_message[0];
				int meta_length = meta_char_length * 16;
				rest_of_message = rest_of_message.substr(1);
				int length_missing = meta_length - rest_of_message.length();
				while(length_missing > 0){
					int len = read(sockTCP, &(tcp_buffer[0]), length_missing);		
					if(len == 0) exit(0);
					tcp_buffer[len] = 0;
					rest_of_message += std::string(tcp_buffer,len);
					length_missing -= len;
				}
				std::string metadate = rest_of_message.substr(0,meta_length);
				set_new_title(metadate);
				rest_of_message = rest_of_message.substr(meta_length);
			}
		} else {
			pthread_mutex_unlock(&mutex);
		}
	}
	return NULL;
}

int main(int argc, char* argv[]){
	
	if(argc != PARAMETERS){
		syserr("Wrong amount of parameters");
	}
	host = argv[1];
	path = argv[2];
	r_port = argv[3];
	file = argv[4];
	m_port = argv[5];

	std::string request_builder = std::string("GET ") + std::string(path) + std::string(" HTTP/1.1\n");
	char* end;
	int num = strtol(argv[3], &end, 10); 
	if (end == argv[1] || *end != '\0' || num < 0){
		syserr("Port number is not a positive integer");
	}
	std::filebuf* fb = new std::filebuf;
	if(strcmp("-",file) != 0){
		fb->open(file, std::ios::out);
		std::ostream* os = new std::ostream(fb);
		output = os;
	}

	num = strtol(argv[5], &end, 10); 
	if (end == argv[1] || *end != '\0' || num < 0){
		syserr("Port number is not a positive integer");
	}

	if(strcmp("yes",argv[6]) != 0 && strcmp("no",argv[6]) != 0){
		syserr("md must be yes or no");
	} else {
		md = strcmp("no",argv[6]);
		if(md) request_builder += std::string("Icy-MetaData:1\n");
		request_builder += std::string("\n");
		for(int i = 0; i < request_builder.length(); i++)
			http_request[i] = request_builder[i];
		http_request[request_builder.length()] = 0;
	}

	for(int i = 0; i<HEADER_BUFFER_SIZE + 1; i++) header_buffer[i] = 0;

	// Connect to the radio by TCP
	memset(&addr_hints, 0, sizeof(struct addrinfo));
	addr_hints.ai_family = AF_INET; // IPv4
	addr_hints.ai_socktype = SOCK_STREAM;
	addr_hints.ai_protocol = IPPROTO_TCP;
	int err = getaddrinfo(host, r_port, &addr_hints, &addr_result);

	sockTCP = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);

	if(err < 0 || sockTCP < 0){
		syserr("Problem with TCP connection");
	}

	connect(sockTCP, addr_result->ai_addr, addr_result->ai_addrlen);
	

	// Setting UDP connection
	sockUDP = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket

	server_address.sin_family = AF_INET; // IPv4
	server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
	server_address.sin_port = htons(atoi(m_port)); // default port for receiving is PORT_NUM

	err = bind(sockUDP, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address));

	if(err < 0 || sockUDP < 0){
		syserr("Problem with UDP connection");
	}
	// Creating threads
	pthread_attr_t* attr = (pthread_attr_t*) malloc(sizeof(pthread_attr_t));
	pthread_attr_init(attr);
	pthread_mutex_init(&mutex,0);
	pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);
	void* retval;
	try{
		pthread_create(&UDPthread, attr, runUDP, 0);
	
		if(md) pthread_create(&TCPthread, attr, runTCPwithmetadate, 0);
		else pthread_create(&TCPthread, attr, runTCPwithoutmetadate, 0);
	} catch(int ret){
		//fb->close();
		free(attr);
		free(addr_result);
		delete fb;
		delete output;
		return ret;
	}
	//fb->close();
	pthread_join(UDPthread, &retval);
	pthread_join(TCPthread, &retval);
	free(attr);
	free(addr_result);
	delete fb;
	delete output;

	return 0;
}
