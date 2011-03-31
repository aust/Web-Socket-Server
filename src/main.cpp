#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <string>
#include <memory>
#include <vector>
#include <openssl/md5.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/thread.hpp>
#include <ctime>
#include <cstdlib>

class Server;
class Client;
typedef Server* server_raw_ptr;

static std::string GetOrigin( std::string& buffer )
{
	size_t pos = buffer.find( "Origin: " ) + sizeof( "Origin: " ) - 1;
	if ( pos == std::string::npos )
		return std::string( "" );

	return std::string( buffer.begin() + pos, buffer.begin() +
		buffer.find( "\r\n", pos ) );
}
// Sec-WebSocket-Key1
uint32_t GetKey1( std::string& buffer )
{
	size_t pos = buffer.find( "Sec-WebSocket-Key1: " );
	if ( pos == std::string::npos )
		return 0;

	pos += sizeof( "Sec-WebSocket-Key1: " ) - 1;
	size_t end_pos = buffer.find( "\r\n", pos );
	if ( end_pos == std::string::npos )
		return 0;

	std::string key( buffer.begin() + pos, buffer.begin() + end_pos );

	uint32_t space_count = 0;
	uint32_t key1 = 0;
	for ( size_t i = 0; i < key.length(); i++ )
	{
		if ( ' ' == key[i] )
			space_count++;
		else if ( 47 < key[i] && 58 > key[i] )
			key1 = key1 * 10 + ( key[i] - 48 );	
	}

	if ( space_count < 1)
		return 0;

	return key1 / space_count;
}

// Sec-WebSocket-Key2
uint32_t GetKey2( std::string& buffer )
{
	size_t pos = buffer.find( "Sec-WebSocket-Key2: " );
	if ( pos == std::string::npos )
		return 0;

	pos += sizeof( "Sec-WebSocket-Key2: " ) - 1;
	size_t end_pos = buffer.find( "\r\n", pos );
	if ( end_pos == std::string::npos )
		return 0;

	std::string key( buffer.begin() + pos, buffer.begin() + end_pos );

	uint32_t space_count = 0;
	uint32_t key2 = 0;
	for ( size_t i = 0; i < key.length(); i++ )
	{
		if ( ' ' == key[i] )
			space_count++;
		else if ( 47 < key[i] && 58 > key[i] )
			key2 = key2 * 10 + ( key[i] - 48 );
	}

	if ( space_count < 1 )
		return 0;

	return key2 / space_count;
}

std::string CreateClientKey( std::string& buffer );

std::string GetHost( std::string& buffer )
{
	size_t pos = buffer.find( "Host: " );
	if ( pos == std::string::npos )
		return std::string( "" );

	pos += sizeof( "Host: " ) - 1;
	size_t end_pos = buffer.find( "\r\n", pos );
	if ( end_pos == std::string::npos )
		return std::string( "" );

	return std::string( buffer.begin() + pos,
		buffer.begin() + end_pos );
}

std::vector<uint8_t> CreateServerHandshake( std::string& buffer )
{
	std::string tmp_handshake;

	tmp_handshake = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
		"Upgrade: WebSocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Origin: " + GetOrigin( buffer ) + "\r\n"
		"Sec-WebSocket-Location: ws://" + GetHost( buffer ) + "/\r\n\r\n"
		+ CreateClientKey( buffer );
	
	std::vector<uint8_t> handshake( tmp_handshake.begin(),
		tmp_handshake.end() );

	return handshake;
}

std::string CreateClientKey( std::string& buffer )
{
	size_t pos = buffer.find( "\r\n\r\n" );
	if ( pos == std::string::npos )
		return std::string( "" );

	std::string key( buffer.begin() + pos + 4, buffer.begin() + pos + 12 );
	if ( key.size() != 8 )
		return std::string( "" );

	uint32_t key1 = GetKey1( buffer );
	uint32_t key2 = GetKey2( buffer );

	if ( !key1 || !key2 )
		return std::string( "" );

	std::vector<uint8_t> unhashed_key;
	unhashed_key.push_back( ( key1 & 0xff000000 ) >> 24 );
	unhashed_key.push_back( ( key1 & 0xff0000 ) >> 16 );
	unhashed_key.push_back( ( key1 & 0xff00 ) >> 8 );
	unhashed_key.push_back( key1 & 0xff );
	unhashed_key.push_back( ( key2 & 0xff000000 ) >> 24 );
	unhashed_key.push_back( ( key2 & 0xff0000 ) >> 16 );
	unhashed_key.push_back( ( key2 & 0xff00 ) >> 8 );
	unhashed_key.push_back( key2 & 0xff );
	unhashed_key.insert( unhashed_key.end(), key.begin(), key.end() );

	unsigned char hash[17];
	MD5( &unhashed_key[0], 16, hash );
	hash[16] = '\0';

	return std::string( reinterpret_cast<char*>( hash ) );
}

class Client
{
public:
	typedef std::shared_ptr<Client> ptr;
	Client( boost::asio::io_service& );
	Client( boost::asio::io_service&, server_raw_ptr const );
	~Client();
	static ptr Create( boost::asio::io_service& );
	static ptr Create( boost::asio::io_service&, server_raw_ptr const );

	boost::asio::ip::tcp::socket& Socket();
	void Start();
	std::vector<uint8_t> Wrap( std::string& data );
	std::vector<uint8_t> Wrap( std::stringstream& data );

private:
	boost::asio::ip::tcp::socket socket_;
	Server* server_;
	char read_raw_buffer_[4096];
	std::string read_buffer_;
	bool handshake_;
	uint32_t id_;
	
	void StartRead();
	void HandleRead( const boost::system::error_code&, std::size_t );
};

class Server
{
public:
	typedef Server* raw_ptr;
	typedef std::shared_ptr<Server> ptr;
	typedef std::vector<char> byte_array;
	typedef void ( *client_message_handler )( raw_ptr, Client::ptr, byte_array& );
	Server( boost::asio::io_service& io_service, const char* host, unsigned short port,
		client_message_handler client_message_handler_cb );
	std::vector<Client::ptr>& client_list();
	void remove_client( std::vector<Client::ptr>::iterator iter );

private:
	std::vector<Client::ptr> client_list_;
	boost::asio::io_service& io_service_;
	boost::asio::ip::tcp::acceptor acceptor_;
	std::string host_;
	unsigned short port_;
	client_message_handler client_message_handler_cb_;
	Client::ptr current_client_ptr_;

	void StartAccept();
	void HandleAccept( const boost::system::error_code& );
};

Client::Client( boost::asio::io_service& io_service )
	: socket_( io_service ), handshake_( false ) { }

Client::Client( boost::asio::io_service& io_service, server_raw_ptr const server )
	: socket_( io_service ), server_( server ), handshake_( false ) { }

Client::~Client() { }

Client::ptr Client::Create( boost::asio::io_service& io_service )
{
	return Client::ptr( new Client( io_service ) );
}

Client::ptr Client::Create( boost::asio::io_service& io_service,
	server_raw_ptr const server )
{
	return Client::ptr( new Client( io_service, server ) );
}

boost::asio::ip::tcp::socket& Client::Socket()
{
	return socket_;
}

void Client::Start()
{
	StartRead();
}

void Client::StartRead()
{
	socket_.async_receive( boost::asio::buffer( read_raw_buffer_, 4096 ),
		boost::bind( &Client::HandleRead, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred ) );
}

std::vector<uint8_t> Client::Wrap( std::string& data )
{
	std::vector<uint8_t> tmp_data;
	tmp_data.push_back( '\x00' );
	for ( size_t i = 0; i < data.size(); i++)
		tmp_data.push_back( data[i] );
	tmp_data.push_back( '\xFF');
	return tmp_data;
}

std::vector<uint8_t> Client::Wrap( std::stringstream& data )
{
	std::vector<uint8_t> tmp_data;
	std::string tmp_str = data.str();

	tmp_data.push_back( '\x00' );
	for ( size_t i = 0; i < tmp_str.size(); i++)
		tmp_data.push_back( tmp_str[i] );
	tmp_data.push_back( '\xFF');
	return tmp_data;
}

void Client::HandleRead( const boost::system::error_code& error,
	std::size_t bytes_transferred )
{
	// Do something with read
	if ( !error && bytes_transferred > 0 )
	{
		if ( !handshake_ )
		{
			read_buffer_.insert( read_buffer_.begin(), read_raw_buffer_,
				read_raw_buffer_ + bytes_transferred );
			std::vector<uint8_t> handshake =
				CreateServerHandshake( read_buffer_ );

			socket_.send( boost::asio::buffer( handshake, handshake.size() ) );
			handshake_ = true;
			read_buffer_.clear();

			// Call callback function for initial handshake later on
			srand( time( 0 ) );
			id_ = rand();

			std::stringstream ss_reg;
			ss_reg << "{\"cmd\":\"register\",\"data\":{\"id\":\""
				<< id_ << "\"}}";
			std::vector<uint8_t> reg_buf = Wrap( ss_reg );
			socket_.send( boost::asio::buffer( reg_buf, reg_buf.size() ) );
		}
		else
		{
			char* read_raw_buffer = read_raw_buffer_;

			// Trivial check: Does data exist in a buffer and does
			// the packet have valid starting form?
			if ( !read_buffer_.size() && '\x00' != *read_raw_buffer )
			{
				// Invalid format, close connection
				std::cout << "Invalid format!" << std::endl;
				socket_.close();
				return;
			}
			// Buffered data exists or we have a valid starting point
			else
			{
				// Could be multiple packets within the raw buffer, we'll extract
				// them one at a time and handle each one with the callback
				do {
					// Skip \x00 if it exists
					if ( *read_raw_buffer == '\x00' )
					{
						read_raw_buffer++;
						bytes_transferred--;
					}

					// Buffer data in case we need to get more data later
					while ( *read_raw_buffer != '\xFF' && bytes_transferred > 0 )
					{
						read_buffer_ += *read_raw_buffer++;
						bytes_transferred--;
					}

					// Are we finished buffering this item or do we come back later?
					if ( *read_raw_buffer == '\xFF' )
					{
						read_raw_buffer++;
						bytes_transferred--;

						// Callback . . .
						std::cout << "Callback: '" << read_buffer_ << "'" << std::endl;
						std::vector<uint8_t> write_buffer_( read_buffer_.begin(),
							read_buffer_.end() );
						write_buffer_.insert( write_buffer_.begin(), '\x00'  );
						write_buffer_.push_back( '\xFF' );
						socket_.send( boost::asio::buffer( write_buffer_,
							write_buffer_.size() ) );
						for ( std::vector<Client::ptr>::iterator iter =
							server_->client_list().begin();
							iter != server_->client_list().end(); ++iter )
						{
							if ( (*iter).get() != this )
							{
								// check if clien is safe to write to
								if ( (*iter)->socket_.is_open() )
								{
									try
									{
										(*iter)->socket_.send( boost::asio::buffer(
											write_buffer_, write_buffer_.size() ) );
									}
									catch (...)
									{
										// Remove client from list, something went
										// wrong.
										(*iter)->socket_.close();
										iter = server_->client_list().erase( iter );
									}
								}
								else
									iter = server_->client_list().erase( iter );
							}

							if ( iter == server_->client_list().end() )
							{
								std::cout << "Found end of client list." << std::endl;
								break;
							}
						}

						// Prepare buffer for more possible data within this packet 
						read_buffer_.clear();

						// We are expecting another packet, if read_raw_buffer is anything else
						// then the client has sent invalid data
						if ( bytes_transferred > 0 && *read_raw_buffer != '\x00' )
						{
							socket_.close();
							// tricky stuff here, delete socket from list
							return;
						}	
					}
					// Continue buffering transferred data until we're out of data to parse
				} while ( bytes_transferred > 0 );
			}
		}
	}
	else
	{
		socket_.close();
		std::cout << error.message() << std::endl;
		return;
	}

	StartRead();
}

Server::Server( boost::asio::io_service& io_service, const char* host, unsigned short port,
	client_message_handler client_message_handler_cb )
	: io_service_( io_service ), acceptor_( io_service ), host_( host ), port_( port ),
	client_message_handler_cb_( client_message_handler_cb )
{
	acceptor_.open( boost::asio::ip::tcp::v4() );
	acceptor_.bind( boost::asio::ip::tcp::endpoint( boost::asio::ip::address::from_string( host ), port ) );
	acceptor_.listen();
	StartAccept();
}

std::vector<Client::ptr>& Server::client_list()
{
	return client_list_;
}

void Server::remove_client( std::vector<Client::ptr>::iterator iter )
{
	io_service_.post( boost::bind( &std::vector<Client::ptr>::erase, &client_list_,
		iter ) );
}

void Server::StartAccept()
{
	current_client_ptr_ = Client::Create( io_service_, this );
	acceptor_.async_accept( current_client_ptr_->Socket(),
		boost::bind( &Server::HandleAccept, this, boost::asio::placeholders::error ) );
}

void Server::HandleAccept( const boost::system::error_code& error )
{
	if ( !error )
	{
		std::cout << "Client connected: " << client_list_.size() + 1 <<
			" client(s) connected." << std::endl;	
		client_list_.push_back( current_client_ptr_ );
		current_client_ptr_->Start();
		StartAccept();
	}
	else
	{
		std::cout << error.message() << std::endl;
	}
}

int main( int arg, char** argv )
{
	boost::asio::io_service io_service;
	Server s( io_service, argv[1], atoi( argv[2] ), 0 );

	for (;;)
	{
		io_service.run();
	}
	return 0;
}
