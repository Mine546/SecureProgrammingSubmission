//this is just some code chat gpt made and I was using to see if 
//websocket, openssl and json were were actually being seen (which i think they are),
//I have no idea if its usable. I'm not sure if you guys have to download anything,
//or if its fine now that I've put everything vcpkg (which is like a management
//system for websockets etc)

#include <iostream>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using websocketpp::client;
using websocketpp::connection_hdl;

class SimpleClient {
public:
    SimpleClient() {
        m_client.init_asio();
        m_client.set_open_handler(std::bind(&SimpleClient::on_open, this, std::placeholders::_1));
        m_client.set_message_handler(std::bind(&SimpleClient::on_message, this, std::placeholders::_1, std::placeholders::_2));
    }

    void run(const std::string &uri) {
        websocketpp::lib::error_code ec;
        auto conn = m_client.get_connection(uri, ec);
        if (ec) {
            std::cout << "Could not create connection: " << ec.message() << std::endl;
            return;
        }

        m_client.connect(conn);
        m_client.run();
    }

private:
    client<websocketpp::config::asio> m_client;

    void on_open(connection_hdl hdl) {
        std::cout << "Connection opened!" << std::endl;

        // Create and send a JSON message
        json msg;
        msg["type"] = "hello";
        msg["message"] = "Hello, WebSocket!";
        m_client.send(hdl, msg.dump(), websocketpp::frame::opcode::text);
    }

    void on_message(connection_hdl hdl, client<websocketpp::config::asio>::message_ptr msg) {
        std::cout << "Received message: " << msg->get_payload() << std::endl;
    }
};

int main() {
    SimpleClient client;
    client.run("ws://localhost:8001");  // Change this to your server address
    return 0;
}
