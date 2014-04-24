// RF22AES.cpp
//
// Define addressed datagram
// 
// Part of the Arduino RF22 library for operating with HopeRF RF22 compatible transceivers 
// (see http://www.hoperf.com)
// RF22Datagram will be received only by the addressed node or all nodes within range if the 
// to address is RF22_BROADCAST_ADDRESS
//
// Author: Jeffrey Minton (jeff.minton@blinkingbox.net)
// Copyright (C) 2011 Jeffrey Minton
// $Id: RF22AES.cpp,v 1.4 2011/02/15 04:51:59 mikem Exp $

#include <RF22AES.h>
#include <SPI.h>
#include <aJSON.h>
#include <MemoryFree.h>

#define DELAY_TIME 0

extern void freeMem( char* message, int delay_time = DELAY_TIME );
extern void freeMem( char letter, int delay_time = DELAY_TIME );
extern void freeMem( int val, int delay_time = DELAY_TIME );
extern void freeMem( const __FlashStringHelper *message, int delay_time = DELAY_TIME );


RF22AES::key_set_t RF22AES::default_keys = {
    { 63, 5, 221, 227, 216, 136, 34, 84, 133, 20, 241, 251, 65, 101, 242, 148 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};


////////////////////////////////////////////////////////////////////
// Constructors
RF22AES::RF22AES( uint8_t thisAddress, uint8_t slaveSelectPin, uint8_t interrupt) 
    : RF22Mesh(thisAddress, slaveSelectPin, interrupt)
{
}

////////////////////////////////////////////////////////////////////
// Public methods

boolean RF22AES::init()
{
    
    keys_synced = 0;
    boolean ret = RF22Mesh::init();
    if( ret ) {
        if( _thisAddress == 0 ) {
            ret = get_address();
            if( !ret ) {
                return ret;
            }
        }
        gen_iv();
        gen_key();
        ret = sync_iv();
        Serial.println( ret );
        if( !ret ) {
            Serial.println( F( "sync_iv fail" ) );
            return ret;
        }
        ret = sync_key();
        Serial.println( ret );
        if( !ret ) {
            Serial.println( F( "sync_key fail" ) );
            return ret;
        }
        keys_synced = 1;
    }

    return ret;
}



////////////////////////////////////////////////////////////////////
// Discovers a route to the destination (if necessary), sends and 
// waits for delivery to the next hop (but not for delivery to the final destination)
uint8_t RF22AES::sendtoWait(uint8_t* buf, uint8_t len, uint8_t address)
{
    freeMem( F( "RF22AES::sendtoWait" ) );
    uint8_t blocks = ( len / 16 ) + 1;

    clear_buf( global_msg_buffer, 256 );

    memcpy( global_msg_buffer, buf, len );

/*
    if (len > RF22_MESH_MAX_MESSAGE_LEN)
	return RF22_ROUTER_ERROR_INVALID_LENGTH;
*/
    Serial.println( F( "before enc" ) );
    for( int i = 0; i < ( blocks * 16 ); i++ ) {
        Serial.print( global_msg_buffer[i], HEX );
        Serial.print( F( ", " ) );
    }
    Serial.println( F( "" ) );

    if( keys_synced == 1 ) {
        freeMem( F( "encrypt" ) );
        freeMem( F( "personal keys" ) );
        aes128_cbc_enc( keys.key, keys.iv, global_msg_buffer, blocks * 16 );
    } else {
        freeMem( F( "encrypt" ) );
        freeMem( F( "default keys" ) );
        aes128_cbc_enc( default_keys.key, default_keys.iv, global_msg_buffer, blocks * 16 );
    }

    Serial.println( F( "after enc" ) );
    for( int i = 0; i < ( blocks * 16 ); i++ ) {
        Serial.print( global_msg_buffer[i], HEX );
        Serial.print( ", " );
    }
    Serial.println( F( "" ) );
    
    return RF22Mesh::sendtoWait( global_msg_buffer, blocks * 16, address );
}


////////////////////////////////////////////////////////////////////
boolean RF22AES::recvfromAck(uint8_t* buf, uint8_t* len, uint8_t* source, uint8_t* dest, uint8_t* id, uint8_t* flags)
{     
    uint8_t ret, global_msg_buffer_len = GLOBAL_BUFFER_SIZE, blocks;
    
    clear_buf( global_msg_buffer, 256 );

    ret = RF22Mesh::recvfromAck( global_msg_buffer, &global_msg_buffer_len, source, dest );

    if( ret ) {
        Serial.println( F( "before dec" ) );
        for( int i = 0; i < global_msg_buffer_len; i++ ) {
            Serial.print( global_msg_buffer[i], HEX );
            Serial.print( F( ", " ) );
        }
        Serial.println( F( "" ) );

        blocks = ( global_msg_buffer_len / 16 ) + 1;

        if( keys_synced == 1 ) {
            freeMem( F( "decrypt" ) );
            freeMem( F( "personal keys" ) );
            aes128_cbc_dec( keys.key, keys.iv, global_msg_buffer, blocks * 16 );
        } else {
            freeMem( F( "decrypt" ) );
            freeMem( F( "default keys" ) );
            aes128_cbc_dec( default_keys.key, default_keys.iv, global_msg_buffer, blocks * 16 );
        }

        Serial.println( F( "after dec" ) );
        for( int i = 0; i < global_msg_buffer_len; i++ ) {
            Serial.print( global_msg_buffer[i], HEX );
            Serial.print( F( ", " ) );
        }
        Serial.println( F( "" ) );
              
        memcpy( buf, global_msg_buffer, (size_t) len );
    }

    return ret;
}

////////////////////////////////////////////////////////////////////
boolean RF22AES::recvfromAckTimeout(uint8_t* buf, uint8_t* len, uint16_t timeout, uint8_t* from, uint8_t* to, uint8_t* id, uint8_t* flags)
{  
    freeMem( F( "RF22AES:recvfromAckTimeout" ) );
    unsigned long starttime = millis();
    while ((millis() - starttime) < timeout)
    {
	if (recvfromAck(buf, len, from, to, id, flags))
	    return true;
    }
    return false;
}


////////////////////////////////////////////////////////////////////
void RF22AES::setKey( uint8_t *key ) {
    memcpy( (void *) keys.key, (void *) key, 16 );
}


////////////////////////////////////////////////////////////////////
void RF22AES::setIV( uint8_t *iv ) {
    memcpy( (void *) keys.iv, (void *) iv, 16 );
}


////////////////////////////////////////////////////////////////////
void RF22AES::gen_iv() {
    Serial.println( F( "gen IV" ) );
    for( int i = 0; i < 16; i++ ) {
        keys.iv[i] = random( 256 );
        freeMem( keys.iv[i] );
    }    
}


////////////////////////////////////////////////////////////////////
void RF22AES::gen_key() {
    Serial.println( F( "gen KEY" ) );
    for( int i = 0; i < 16; i++ ) {
        keys.key[i] = random( 256 );
        freeMem( keys.key[i] );
    }    
}

////////////////////////////////////////////////////////////////////
boolean RF22AES::sync_iv() {

    Serial.println( F( "sync iv" ) );
    uint8_t len = GLOBAL_BUFFER_SIZE, source, dest, msg_len, type, key_synced = 0, ret;
    char *json_str;
    aJsonObject *root;

    root = aJson.createObject();
    aJson.addNumberToObject( root, F( "t" ), (uint8_t) SYNC_IV );
    aJson.addNumberToObject( root, F( "m" ), (uint8_t) me );
    aJson.addItemToObject( root, F( "i" ), aJson.createIntArray( keys.iv, 16 ) );
    json_str = aJson.print( root );
    aJson.deleteItem( root );
    Serial.println( json_str );
    Serial.println( strlen( json_str ) );

    while( key_synced == 0 )
    {
        ret = sendtoWait( (uint8_t *) json_str, (uint8_t) strlen( json_str ), server_address );
        if( ret == RF22_ROUTER_ERROR_NONE ) {
            for( int i = 0; i < 4 && key_synced == 0; i++ )
            {
                if( recvfromAckTimeout( global_msg_buffer, &len, 500, &source, &dest ) == true ) {
                    Serial.println( (const char*) global_msg_buffer );
                    root = aJson.parse( (char *) global_msg_buffer );
                    if( (uint8_t) aJson.getObjectItem( root, F( "t" ) )->valueint == (uint8_t) SYNC_IV ) {
                        //json_str = aJson.print( root );
                        //Serial.println( json_str );
                        //Serial.println( strlen( json_str ) );
                        key_synced = 1;
                    }
                } else {
                    Serial.println( F( "no receive" ) );
                }
            }
        }
    }
    
    free( json_str );
    aJson.deleteItem( root );
    return true;
}


////////////////////////////////////////////////////////////////////
boolean RF22AES::sync_key() {


    Serial.println( F( "sync key" ) );
    uint8_t len = GLOBAL_BUFFER_SIZE, source, dest, msg_len, type, key_synced = 0, ret;
    char *json_str;
    aJsonObject *root;

    root = aJson.createObject();
    aJson.addNumberToObject( root, F( "t" ), (uint8_t) SYNC_KEY );
    aJson.addNumberToObject( root, F( "m" ), (uint8_t) me );
    aJson.addItemToObject( root, F( "i" ), aJson.createIntArray( keys.key, 16 ) );
    json_str = aJson.print( root );
    aJson.deleteItem( root );
    Serial.println( json_str );
    Serial.println( strlen( json_str ) );

    while( key_synced == 0 )
    {
        ret = sendtoWait( (uint8_t *) json_str, (uint8_t) strlen( json_str ), server_address );
        if( ret == RF22_ROUTER_ERROR_NONE ) {
            for( int i = 0; i < 4 && key_synced == 0; i++ )
            {
                if( recvfromAckTimeout( global_msg_buffer, &len, 500, &source, &dest ) == true ) {
                    Serial.println( (const char*) global_msg_buffer );
                    root = aJson.parse( (char *) global_msg_buffer );
                    if( (uint8_t) aJson.getObjectItem( root, F( "t" ) )->valueint == (uint8_t) SYNC_KEY ) {
                        //json_str = aJson.print( root );
                        //Serial.println( json_str );
                        //Serial.println( strlen( json_str ) );
                        key_synced = 1;
                    }
                } else {
                    Serial.println( F( "no receive" ) );
                }
            }
        }
    }
    
    free( json_str );
    aJson.deleteItem( root );
    return true;
}




///////////////////////////////////////////////////////////////////
void pad( char *json_str ) {
    

}
