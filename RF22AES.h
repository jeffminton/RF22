// RF22AES.h
//
// Author: Mike McCauley (mikem@airspayce.com)
// Copyright (C) 2011 Mike McCauley
// $Id: RF22AES.h,v 1.4 2012/05/30 01:51:25 mikem Exp $

#ifndef RF22AES_h
#define RF22AES_h

//#define NOFUNC

#include <RF22Mesh.h>
#include <AESLib.h>


/////////////////////////////////////////////////////////////////////
/// \class RF22AES RF22AES.h <RF22AES.h>
/// \brief RF22 subclass to enable sending and receiving of encrypted messages
///
/// Extends RF22Mesh to add encryption and decryption of messages
///
/// Part of the Arduino RF22 library for operating with HopeRF RF22 compatible transceivers 
/// (see http://www.hoperf.com)
class RF22AES : public RF22Mesh
{
public:





    /// Constructor. 
    /// \param[in] key The AES key to use for encryption and decryption
    /// \param[in] iv the initialization vector used for encryption and decryption
    /// \param[in] thisAddress The address to assign to this node. Defaults to 0
    /// \param[in] slaveSelectPin the Arduino pin number of the output to use to select the RF22 before
    /// accessing it. Defaults to the normal SS pin for your Arduino (D10 for Diecimila, Uno etc, D53 for Mega)
    /// \param[in] interrupt The interrupt number to use. Default is interrupt 0 (Arduino input pin 2)
    RF22AES( uint8_t thisAddress = 0, uint8_t slaveSelectPin = SS, uint8_t interrupt = 0 );

    /// Initialises this instance and the radio module connected to it.
    /// Overrides the init() function in RF22.
    /// Internally calls the RF22Mesh::init method
    boolean init();


    /// Sends a message to the destination node. Initialises the RF22Router message header 
    /// (the SOURCE address is set to the address of this node, HOPS to 0) and calls 
    /// route() which looks up in the routing table the next hop to deliver to.
    /// If no route is known, initiates route discovery and waits for a reply.
    /// Then sends the message to the next hop
    /// Then waits for an acknowledgement from the next hop 
    /// (but not from the destination node (if that is different).
    /// \param [in] buf The application message data
    /// \param [in] len Number of octets in the application message data. 0 is permitted
    /// \param [in] dest The destination node address
    /// \return The result code:
    ///         - RF22_ROUTER_ERROR_NONE Message was routed and deliverd to the next hop 
    ///           (not necessarily to the final dest address)
    ///         - RF22_ROUTER_ERROR_NO_ROUTE There was no route for dest in the local routing table
    ///         - RF22_ROUTER_ERROR_UNABLE_TO_DELIVER Noyt able to deliver to the next hop 
    ///           (usually because it dod not acknowledge due to being off the air or out of range
    uint8_t sendtoWait(uint8_t* buf, uint8_t len, uint8_t dest);

    /// Starts the receiver if it is not running already.
    /// If there is a valid application layer message available for this node (or RF22_BROADCAST_ADDRESS), 
    /// send an acknowledgement to the last hop
    /// address (blocking until this is complete), then copy the application message payload data
    /// to buf and return true
    /// else return false. 
    /// If a message is copied, *len is set to the length..
    /// If from is not NULL, the originator SOURCE address is placed in *source.
    /// If to is not NULL, the DEST address is placed in *dest. This might be this nodes address or 
    /// RF22_BROADCAST_ADDRESS. 
    /// This is the preferred function for getting messages addressed to this node.
    /// If the message is not a broadcast, acknowledge to the sender before returning.
    /// \param[in] buf Location to copy the received message
    /// \param[in,out] len Available space in buf. Set to the actual number of octets copied.
    /// \param[in] source If present and not NULL, the referenced uint8_t will be set to the SOURCE address
    /// \param[in] dest If present and not NULL, the referenced uint8_t will be set to the DEST address
    /// \param[in] id If present and not NULL, the referenced uint8_t will be set to the ID
    /// \param[in] flags If present and not NULL, the referenced uint8_t will be set to the FLAGS
    /// (not just those addressed to this node).
    /// \return true if a valid message was recvived for this node and copied to buf
    boolean recvfromAck(uint8_t* buf, uint8_t* len, uint8_t* source = NULL, uint8_t* dest = NULL, uint8_t* id = NULL, uint8_t* flags = NULL);

    /// Starts the receiver if it is not running already.
    /// Similar to recvfromAck(), this will block until either a valid application layer 
    /// message available for this node
    /// or the timeout expires. 
    /// \param[in] buf Location to copy the received message
    /// \param[in,out] len Available space in buf. Set to the actual number of octets copied.
    /// \param[in] timeout Maximum time to wait in milliseconds
    /// \param[in] source If present and not NULL, the referenced uint8_t will be set to the SOURCE address
    /// \param[in] dest If present and not NULL, the referenced uint8_t will be set to the DEST address
    /// \param[in] id If present and not NULL, the referenced uint8_t will be set to the ID
    /// \param[in] flags If present and not NULL, the referenced uint8_t will be set to the FLAGS
    /// (not just those addressed to this node).
    /// \return true if a valid message was copied to buf
    boolean recvfromAckTimeout(uint8_t* buf, uint8_t* len,  uint16_t timeout, uint8_t* source = NULL, uint8_t* dest = NULL, uint8_t* id = NULL, uint8_t* flags = NULL);

    /// Sets the AES key 
    /// \param[in] key The AES key to use for encryption and decryption
    void setKey( uint8_t *key );

    /// Sets the AES IV (initialization vector)
    /// \param[in] iv the initialization vector used for encryption and decryption
    void setIV( uint8_t *iv );

    /// Generate a 128bit IV used for encryption and decryption
    void gen_iv();

    /// Generate a 128bit Key used for encryption and decryption
    void gen_key();

    /// Synchronize the IV generated by gen_iv with the server
    boolean sync_iv(); 

    /// Synchronize the Key generated by gen_key with the server
    boolean sync_key(); 

    /// Pad the json string to a multiple of 16 for enc and dec
    /// \param[in] json_str the json string to pad
    void pad( char *json_str );

protected:

private:
    /// Temporary mesage buffer
    static uint8_t _tmpMessage[RF22_ROUTER_MAX_MESSAGE_LEN];


    typedef struct {
        uint8_t key[16];
        uint8_t iv[16];
    } key_set_t;

    //32B
    static key_set_t default_keys;

    //32B
    key_set_t keys;

    //1B
    uint8_t keys_synced;

    //65B
};

#endif

