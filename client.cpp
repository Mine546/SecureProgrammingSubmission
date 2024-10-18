#include <iostream>
#include <string>
#include <vector>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>


using json = nlohmann::json;
using websocketpp::client;
using websocketpp::connection_hdl;

class ChatClient {
public:
    ChatClient() : counter(0) {
        m_client.init_asio();
        m_client.set_open_handler(std::bind(&ChatClient::on_open, this, std::placeholders::_1));
        m_client.set_message_handler(std::bind(&ChatClient::on_message, this, std::placeholders::_1, std::placeholders::_2));
        load_or_generate_keys();
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
        handle_user_input();
    }
    
    void prompt_user_input(connection_hdl hdl) {
        while (true) {
            std::string message_type;
            std::string sender_fingerprint = get_sender_fingerprint();
            std::cout << "Enter message type (public/private): ";
            std::cin >> message_type;

            if (message_type == "public") {
                std::cin.ignore(); // Clear newline from input buffer
                std::string public_message;
                std::cout << "Enter your public message: ";
                std::getline(std::cin, public_message);
                send_public_chat_message(hdl, public_message);
            } else if (message_type == "private") {
                std::cin.ignore(); // Clear newline from input buffer
                std::string encrypted_message;
                std::cout << "Enter your encrypted message: ";
                std::getline(std::cin, encrypted_message);

                // Get recipient(s)
                std::string recipient_input;
                std::cout << "Enter recipient(s) (comma-separated): ";
                std::getline(std::cin, recipient_input);
                std::vector<std::string> recipients = split_recipients(recipient_input);
                send_chat_message(hdl, encrypted_message, recipients, sender_fingerprint);
            } else if (message_type == "/quit") {
                std::cout << "Quitting chat..." << std::endl;
                m_client.close(hdl, websocketpp::close::status::normal, "Goodbye!");
                break;
            } else {
                std::cout << "Invalid message type. Please try again." << std::endl;
            }
        }
    }

private:
    client<websocketpp::config::asio> m_client;
    int counter;
    connection_hdl hdl;
    websocketpp::lib::error_code ec;
    RSA* rsa_key;

    void on_open(connection_hdl hdl) {
        send_hello(hdl);
        std::cout << "Connection established. You can start sending messages." << std::endl;
        prompt_user_input(hdl); // Start prompting for user input
    }

    void on_message(connection_hdl hdl, client<websocketpp::config::asio>::message_ptr msg) {
        auto received_msg = json::parse(msg->get_payload());
        if (received_msg["type"] == "client_list") {
            handle_client_list(received_msg);
        } else if (received_msg["data"]["type"] == "public_chat") {
            handle_public_chat(received_msg);
        } else if (received_msg["data"]["type"] == "chat" ) {
            handle_private_chat(received_msg);
        } else { 

        }
    }
    
    void handle_user_input() {
        std::string input;
        while (std::getline(std::cin, input)) {
            if (input == "/quit") {
                std::cout << "Quitting chat..." << std::endl;
                m_client.close(hdl, websocketpp::close::status::normal, "Goodbye!");
                break;
            }
        }
    }

    void send_hello(connection_hdl hdl) {
        json helloMessage;
        helloMessage["data"]["type"] = "hello";
        helloMessage["data"]["public_key"] = get_public_key();
        std::cout << "Sending Hello Message: " << helloMessage.dump() << std::endl;
        m_client.send(hdl, helloMessage.dump(), websocketpp::frame::opcode::text, ec);
        // send_signed_message(hdl, helloMessage);
    }

    void send_chat_message(connection_hdl hdl, const std::string& chat_message, const std::vector<std::string>& recipients, const std::string& sender_fingerprint) {
    json chat_data;
    chat_data["type"] = "chat";
    chat_data["destination_servers"] = recipients;

    // Prepare the chat object
    json chat_content;
    chat_content["participants"] = { sender_fingerprint }; // Start with the sender's fingerprint
    for (const auto& recipient : recipients) {
        chat_content["participants"].push_back(recipient); // Add recipient fingerprints
    } 
    chat_content["message"] = chat_message;

    std::string aes_key = generate_aes_key(); // Generate AES key
    std::string iv = generate_iv(); // Generate IV
    chat_data["iv"] = base64_encode(reinterpret_cast<const unsigned char*>(iv.c_str()), iv.size());
    
    // Encrypt the AES key and encode it
    std::string encrypted_keys = encrypt_with_rsa(aes_key, recipients);
    chat_data["symm_keys"] = { base64_encode(reinterpret_cast<const unsigned char*>(encrypted_keys.c_str()), encrypted_keys.size()) };
    
    // Encrypt the chat message and encode it
    std::string encrypted_chat = encrypt_with_aes(chat_message, aes_key, iv);
    chat_data["chat"] = base64_encode(reinterpret_cast<const unsigned char*>(encrypted_chat.c_str()), encrypted_chat.size());

    send_signed_message(hdl, chat_data);
    }
    
    void send_public_chat_message(connection_hdl hdl, const std::string& public_message) {
        json public_chat_data;
        public_chat_data["data"]["type"] = "public_chat";
        public_chat_data["data"]["sender"] = get_sender_fingerprint();
        public_chat_data["data"]["message"] = public_message;
        std::cout << "Sending public message: " << public_message << std::endl; 
        send_signed_message(hdl, public_chat_data);
    }

    void send_signed_message(connection_hdl hdl, const json& msg_data) {
        json msg;
        msg["type"] = "signed_data";
        msg["data"] = msg_data;
        msg["counter"] = ++counter;
        msg["signature"] = sign_message(msg_data, msg["counter"]);
        
        
        m_client.send(hdl, msg.dump(), websocketpp::frame::opcode::text);
        if (ec) {
            std::cout << "Error sending signed message: " << ec.message() << std::endl;
        } else {
            std::cout << "" << std::endl; 
        }
    }

    std::string sign_message(const json& data, int counter) {
        std::string data_str = data.dump() + std::to_string(counter);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data_str.c_str()), data_str.size(), hash);

        unsigned char* signature = new unsigned char[RSA_size(rsa_key)];
        unsigned int sig_len;
        RSA_sign(NID_sha256, hash, sizeof(hash), signature, &sig_len, rsa_key);

        std::string encoded_signature = base64_encode(signature, sig_len);
        delete[] signature;
        return encoded_signature;
    }

    std::vector<std::string> split_recipients(const std::string& input) {
        std::vector<std::string> recipients;
        std::istringstream stream(input);
        std::string recipient;
        while (std::getline(stream, recipient, ',')) {
            recipients.push_back(recipient);
        }
        return recipients;
    }

    std::string base64_encode(const unsigned char* input, int length) {
    // Base 64 encoding implementation
        std::string output;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

        while (length--) {
            char_array_3[i++] = *(input++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                    output += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; j < i + 1; j++)
                output += base64_chars[char_array_4[j]];

            while (i++ < 3)
                output += '=';
        }

        return output;
    }

    std::string encrypt_with_rsa(const std::string& aes_key, const std::vector<std::string>& recipients) {
    // Encrypt AES key with recipient's RSA public keys
        std::string encrypted_keys;

        for (const std::string& recipient : recipients) {
            BIO* bio = BIO_new_mem_buf(recipient.data(), static_cast<int>(recipient.size()));
            RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!rsa_public_key) {
                std::cerr << "Failed to read public key." << std::endl;
                continue;
            }

            std::vector<unsigned char> encrypted_aes_key(RSA_size(rsa_public_key));
            int result = RSA_public_encrypt(aes_key.size(), 
                                            reinterpret_cast<const unsigned char*>(aes_key.c_str()), 
                                            encrypted_aes_key.data(), 
                                            rsa_public_key, 
                                            RSA_PKCS1_PADDING);

            RSA_free(rsa_public_key);

            if (result == -1) {
                std::cerr << "RSA encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
                continue;
            }

            encrypted_keys += base64_encode(encrypted_aes_key.data(), result) + ",";
        }

        if (!encrypted_keys.empty()) {
            encrypted_keys.pop_back(); // Remove trailing comma
        }

        return encrypted_keys;
    }
    

    std::string encrypt_with_aes(const std::string& message, const std::string& aes_key, const std::string& iv) {
    // Encrypt message using AES
    AES_KEY encrypt_key;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(aes_key.c_str()), 128, &encrypt_key);

    std::vector<unsigned char> encrypted_message(message.size() + AES_BLOCK_SIZE);
    int num_bytes_encrypted = 0;

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(message.c_str()),
                    encrypted_message.data(),
                    message.size(),
                    &encrypt_key,
                    reinterpret_cast<unsigned char*>(const_cast<char*>(iv.c_str())),
                    AES_ENCRYPT);

    return std::string(reinterpret_cast<char*>(encrypted_message.data()), message.size());
    }
    

    void handle_client_list(const json& response) {
    // Process the client list response from the server
       if (response.contains("data") && response["data"].contains("clients")) {
        std::cout << "Connected clients:" << std::endl;
        for (const auto& client : response["data"]["clients"]) {
            std::cout << "- " << client.get<std::string>() << std::endl;
        }
    } else {
        std::cout << "No client list found in response." << std::endl;
    }
    }

    void handle_public_chat(const json& message) {
        std::cout << "Public chat from " << message["data"]["sender"] << ": " << message["data"]["message"] << std::endl;
    }

    void handle_private_chat(const json& message) {
        // decrypt chat
        std::string encrypted_chat = message["data"]["chat"];
        std::string iv = message["data"]["iv"];
        std::string aes_key = decrypt_with_rsa(message["data"]["symm_keys"][0]);

        std::string decrypted_message = decrypt_with_aes(encrypted_chat, aes_key, iv);
        std::cout << "Encrypted chat received: " << decrypted_message << std::endl;
    }

    std::string base64_decode(const std::string& input) {
        BIO* bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
        BIO* b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines

        std::vector<char> buffer(input.size());
        int decoded_length = BIO_read(bio, buffer.data(), buffer.size());
        BIO_free_all(bio);
        
        if (decoded_length < 0) {
            throw std::runtime_error("Base64 decode failed");
        }

        return std::string(buffer.data(), decoded_length);
    }

    std::string decrypt_with_aes(const std::string& encrypted_message, const std::string& aes_key, const std::string& iv) {
    // Implement AES decryption logic here
        AES_KEY decrypt_key;
        AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(aes_key.c_str()), 128, &decrypt_key);

        std::vector<unsigned char> decrypted_message(encrypted_message.size());
        AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(encrypted_message.c_str()),
                        decrypted_message.data(),
                        encrypted_message.size(),
                        &decrypt_key,
                        reinterpret_cast<unsigned char*>(const_cast<char*>(iv.c_str())),
                        AES_DECRYPT);

        return std::string(reinterpret_cast<char*>(decrypted_message.data()), encrypted_message.size());
    }

    std::string decrypt_with_rsa(const std::string& encrypted_aes_key) {
    // Implement RSA decryption logic here
    std::string decoded_key = base64_decode(encrypted_aes_key);
    std::vector<unsigned char> decrypted_key(RSA_size(rsa_key));

    int result = RSA_private_decrypt(decoded_key.size(),
                                      reinterpret_cast<const unsigned char*>(decoded_key.c_str()),
                                      decrypted_key.data(),
                                      rsa_key,
                                      RSA_PKCS1_PADDING);

    if (result == -1) {
        std::cerr << "RSA decryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }

    return std::string(reinterpret_cast<char*>(decrypted_key.data()), result);
    }

    std::string get_public_key() {
    // Function to export the public key as a PEM string
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio, rsa_key);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_write(bio, "", 0); // Flush BIO

        std::string public_key(bufferPtr->data, bufferPtr->length);
        BIO_free(bio);

    return public_key;
    }

    std::string get_sender_fingerprint() {
    // Function to retrieve the fingerprint of the sender
    // Here you might want to compute a hash of the public key
        std::string public_key = get_public_key();
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(public_key.c_str()), public_key.size(), hash);

        return base64_encode(hash, SHA256_DIGEST_LENGTH);
    }

    void load_or_generate_keys() {
        rsa_key = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    }


    std::string generate_aes_key(int length = 16) {
    std::vector<unsigned char> key(length);
    RAND_bytes(key.data(), length);
    return std::string(reinterpret_cast<char*>(key.data()), key.size());
    }

    std::string generate_iv() {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    RAND_bytes(iv.data(), AES_BLOCK_SIZE);
    return std::string(reinterpret_cast<char*>(iv.data()), iv.size());
    }

};

int main() {
    ChatClient client;
    client.run("ws://localhost:8001");  // Change this to your server address
    return 0;
}