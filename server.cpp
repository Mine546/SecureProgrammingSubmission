#include <iostream>
#include <vector>
#include <set>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <websocketpp/server.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/client.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>

using json = nlohmann::json;
using websocketpp::server;
using websocketpp::connection_hdl;
using boost::asio::ip::tcp;

struct ConnectionHash {
    std::size_t operator()(const connection_hdl& hdl) const {
        return std::hash<websocketpp::connection_hdl::element_type*>()(hdl.lock().get()); 
    }
};
struct ConnectionEqual {
    bool operator()(const connection_hdl& lhs, const connection_hdl& rhs) const {
        return lhs.lock() == rhs.lock();
    }
};

class Server {
public:
    Server() : client_id_counter(0) {
        m_server.init_asio();
        m_server.set_open_handler(std::bind(&Server::on_open, this, std::placeholders::_1));
        m_server.set_close_handler(std::bind(&Server::on_close, this, std::placeholders::_1));
        m_server.set_message_handler(std::bind(&Server::on_message, this, std::placeholders::_1, std::placeholders::_2));
        load_neighbourhood_servers();
    }

    void run(uint16_t port) {
        m_server.listen(port);
        m_server.start_accept();
        m_server.run();
    }

    void send_client_update() {
        json update_msg;
        update_msg["type"] = "client_update";
        update_msg["clients"] = get_client_list();

        for (const auto& neighbour : neighbourhood_servers) {
            send_message_to_server(neighbour, update_msg.dump());
        }
    }

    void send_client_update_request() {
        json request_msg;
        request_msg["type"] = "client_update_request";

        for (const auto& neighbour : neighbourhood_servers) {
            send_message_to_server(neighbour, request_msg.dump());
        }
    }

    void send_server_hello(const std::string& server_address) {
        json hello_msg;
        hello_msg["data"]["type"] = "server_hello";
        hello_msg["data"]["sender"] = server_address;

        send_message_to_server(server_address, hello_msg.dump());
    }

private:
    server<websocketpp::config::asio> m_server;
    std::unordered_map<connection_hdl, std::string, ConnectionHash, ConnectionEqual> client_map; 
    std::vector<std::string> neighbourhood_servers;
    std::atomic<int> client_id_counter;
    std::set<std::string> connected_clients;

    void on_open(connection_hdl hdl) {
        std::cout << "New client connected." << std::endl;
        std::string client_name = "Client " +std::to_string(++client_id_counter);
        client_map[hdl] = client_name;

        broadcast_client_update(client_name);
        send_client_list(hdl); 
        
    }

    void broadcast_client_update(const std::string& new_client_name) {
        json update_msg;
        update_msg["type"] = "client_connected";
        update_msg["clients"] = new_client_name;

        for (const auto& entry : client_map) {
            m_server.send(entry.first, update_msg.dump(), websocketpp::frame::opcode::text);
        }
    }

    void on_close(connection_hdl hdl) {
        std::cout << "Client disconnected." << std::endl;
        auto it = client_map.find(hdl);
        if (it != client_map.end()) {
            std::string client_name = it->second;
            client_map.erase(it);
            std::cout << client_name << " has disconnected." << std::endl;

        if (client_said_hello(client_name)) {
            broadcast_client_update(client_name);
        }
        } else {
            std::cerr << "Client not found in the map." << std::endl;
        }
    }

     void on_message(connection_hdl hdl, server<websocketpp::config::asio>::message_ptr msg) {
        std::string payload = msg->get_payload();
        std::cout << "Received message: " << payload << std::endl;
        auto received_msg = json::parse(msg->get_payload());
        try { 
            if (received_msg["data"]["type"] == "hello") {
                std::cout << "Received Hello message: " << received_msg.dump() << std::endl; 
                handle_hello_msg(hdl, received_msg);    
            } else if (received_msg["data"]["type"] == "signed_data") {
                std::cout << "Received signed data: " << received_msg.dump() << std::endl; 
                handle_signed_data(hdl, received_msg);        
            } else {
                std::cout << "Unknown message received." << std::endl;
            }
        } catch (const json::parse_error& e) {
            std::cout << "Received invalid JSON message." << std::endl;
        }
    }

    void send_json_to_server(const std::string& server_address, const json& msg) {
        std::cout << "Sending JSON to server(s): " << server_address << std::endl;
        // Establish WebSocket or HTTP connection and send the JSON
        websocketpp::client<websocketpp::config::asio> client;
        websocketpp::lib::error_code ec;

        client.init_asio();
        auto conn = client.get_connection(server_address, ec);
        if (ec) {
            std::cout << "Error connecting to server: " << ec.message() << std::endl;
            return;
        }
        client.set_message_handler([](websocketpp::connection_hdl, websocketpp::client<websocketpp::config::asio>::message_ptr msg) {
            std::cout << "Received: " << msg->get_payload() << std::endl;
        });

        client.connect(conn);
        client.run();  // Run the client to ensure the connection is made

        client.send(conn->get_handle(), msg.dump(), websocketpp::frame::opcode::text);
    }

    bool validate_json(const json& msg) {
        if (!msg.contains("type")) {
            std::cout << "Invalid message: Missing 'type'" << std::endl;
            return false;
        }
        if (msg["type"] != "client_list_request" && msg["type"] != "client_update_request" && !msg.contains("data")) {
            std::cout << "Invalid message: Incorrect format" << std::endl;
            return false;
        }
        return true;
    }

    bool validate_message(const json& msg) {
        return msg.contains("data") && msg["data"].contains("chat") && msg["data"].contains("destination_servers");
    }

    std::string create_message(const std::string& chat_message) {
        json msg;
        msg["data"]["chat"] = chat_message;
        return msg.dump(); 
    }
   

    void forward_message(const std::string& chat_message, const std::vector<std::string>& destination_servers) {
        for (const std::string& server_address : destination_servers) {
            std::string message_to_send = create_message(chat_message);
            send_message_to_server(server_address, message_to_send);
        }
    }
    
    void load_neighbourhood_servers() {
        std::ifstream file("neighbourhood_servers.txt");
        std::string server;
        while (std::getline(file, server)) {
            neighbourhood_servers.push_back(server);
        }
    }

void handle_chat_message(connection_hdl hdl, const json& received_msg) {
    if (!validate_message(received_msg)) {
        std::cerr << "Invalid message format." << std::endl;
        return; 
    }

    std::string iv = received_msg["data"]["iv"];
    std::vector<std::string> destination_servers = received_msg["data"]["destination_servers"];
    std::string encrypted_chat = received_msg["data"]["chat"];
    std::vector<std::string> symm_keys = received_msg["data"]["symm_keys"];

    std::cout << "Forwarding chat message to destination servers." << std::endl;

    json forward_msg;
    forward_msg["data"]["type"] = "chat";
    forward_msg["data"]["chat"] = encrypted_chat;
    forward_msg["data"]["iv"] = iv;
    forward_msg["data"]["symm_keys"] = symm_keys;

    forward_message(forward_msg.dump(), destination_servers);
}
    void handle_public_chat_message(connection_hdl hdl, const json& received_msg) {
        std::string sender = received_msg["data"]["sender"];
        std::string public_message = received_msg["data"]["message"];    
        std::cout << "Broadcasting public chat message: " << public_message << std::endl;

        broadcast_public_message(sender, public_message);
    }

    void broadcast_public_message(const std::string& sender, const std::string& message) {
        json broadcast_msg;
        broadcast_msg["data"]["type"] = "public_chat";
        broadcast_msg["data"]["sender"] = sender;
        broadcast_msg["data"]["message"] = message;

        for (const auto& client : client_map) {
            m_server.send(client.first, broadcast_msg.dump(), websocketpp::frame::opcode::text);
        }
    }

    void handle_hello_msg(connection_hdl hdl, const json& received_msg) {
        std::string client_public_key = received_msg["data"]["public_key"];;
        client_map[hdl] = client_public_key;
        std::cout << "Received Hello from client." << client_public_key << std::endl;

        json response_msg;
        response_msg["type"] = "signed_data";
        response_msg["data"]["type"] = "hello_response";
        response_msg["data"]["status"] = "works";

        send_client_update();
        m_server.send(hdl, response_msg.dump(), websocketpp::frame::opcode::text);  
    }

    bool client_said_hello(const std::string& client_name) {
        return connected_clients.find(client_name) != connected_clients.end();
    }

    void handle_signed_data(connection_hdl hdl, const json& received_msg) {
        if (received_msg["data"]["type"] == "chat") {
            handle_chat_message(hdl, received_msg);
        } else if (received_msg["data"]["type"] == "public_chat") {
            handle_public_chat_message(hdl, received_msg);
        } else {
            std::cout << "Unknown signed data type." << std::endl;
        }
    }

    void send_client_list(connection_hdl hdl) {
        json client_list_msg;
        client_list_msg["type"] = "client_list";

        json server_info;
        client_list_msg["servers"] = get_server_client_list();

        m_server.send(hdl, client_list_msg.dump(), websocketpp::frame::opcode::text);
    }

    std::vector<std::string> get_client_list() {
        std::vector<std::string> clients;
        for (const auto& entry : client_map) {
            clients.push_back(entry.second);  // Assuming entry.second holds client's PEM public key
        }        
        return clients;
    }

    json get_server_client_list() {
        json server_list = json::array();
        json this_server;
        this_server["address"] = "localhost"; 
        this_server["clients"] = get_client_list();

        server_list.push_back(this_server);
        return server_list;
    }
    
    void send_message_to_server(const std::string& server_address, const json& message) {
        websocketpp::client<websocketpp::config::asio> ws_client;
        ws_client.init_asio();

        ws_client.set_message_handler([](websocketpp::connection_hdl, websocketpp::client<websocketpp::config::asio>::message_ptr msg) {
            std::cout << "Received: " << msg->get_payload() << std::endl;
        });

        websocketpp::lib::error_code ec;
        auto conn = ws_client.get_connection(server_address, ec);

        if (ec) {
            std::cerr << "Could not create connection to " << server_address << ": " << ec.message() << std::endl;
            return;
        }
        
        ws_client.set_open_handler([&ws_client, message](websocketpp::connection_hdl hdl) {
        ws_client.send(hdl, message.dump(), websocketpp::frame::opcode::text);
        ws_client.close(hdl, websocketpp::close::status::normal, "Done sending"); // Optionally close the connection
    });

        ws_client.connect(conn);

        ws_client.run();
    }
};

int main() {
    Server server;
    server.run(8001);
    return 0;
}
// SERVER_H 