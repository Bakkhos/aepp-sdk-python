from typing import Union
from aeternity.hashing import _int, _binary, _id, encode, decode, encode_rlp, hash_encode, contract_id, decode_rlp
from aeternity.openapi import OpenAPICli
from aeternity.config import ORACLE_DEFAULT_TTL_TYPE_DELTA
from aeternity import identifiers as idf


class TxSigner:
    """
    TxSigner is used to sign transactions
    """

    def __init__(self, account, network_id):
        self.account = account
        self.network_id = network_id

    def encode_signed_transaction(self, transaction, signature):
        """prepare a signed transaction message"""
        tag = bytes([idf.OBJECT_TAG_SIGNED_TRANSACTION])
        vsn = bytes([idf.VSN])
        encoded_signed_tx = encode_rlp(idf.TRANSACTION, [tag, vsn, [signature], transaction])
        encoded_signature = encode(idf.SIGNATURE, signature)
        return encoded_signed_tx, encoded_signature

    def sign_encode_transaction(self, tx):
        """
        Sign, encode and compute the hash of a transaction
        :return: encoded_signed_tx, encoded_signature, tx_hash
        """
        # decode the transaction if not in native mode
        transaction = decode(tx.tx) if hasattr(tx, idf.TRANSACTION) else decode(tx)
        # sign the transaction
        signature = self.account.sign(_binary(self.network_id) + transaction)
        # encode the transaction
        encoded_signed_tx, encoded_signature = self.encode_signed_transaction(transaction, signature)
        # compute the hash
        tx_hash = TxBuilder.compute_tx_hash(encoded_signed_tx)
        # return the
        return encoded_signed_tx, encoded_signature, tx_hash

    #cmk added
    def cosign_encode_transaction(self, tx, other_account):
        """
        Sign, encode and compute the hash of a transaction
        :return: encoded_signed_tx, encoded_signatures, tx_hash
        """
        transaction = decode(tx.tx) if hasattr(tx, "tx") else decode(tx)
        #sign with both keys
        signature1 = self.account.sign(_binary(self.network_id) + transaction)
        signature2 = other_account.sign(_binary(self.network_id) + transaction)
        #encode
        tag = bytes([OBJECT_TAG_SIGNED_TRANSACTION])
        vsn = bytes([VSN])
        encoded_cosigned_tx = encode_rlp("tx", [tag, vsn, sorted([signature1, signature2]), transaction])

        return (encoded_cosigned_tx,
                [encode("sg", signature1), encode("sg", signature2)],
                TxBuilder.compute_tx_hash(encoded_cosigned_tx))

class TxBuilder:
    """
    TxBuilder is used to build and post transactions to the chain.
    """

    def __init__(self, native=False, api: OpenAPICli =None):
        """
        :param native: if the transactions should be built by the sdk (True) or requested to the debug api (False)
        """
        if not native and api is None:
            raise ValueError("A initialized api rest client has to be provided to build a transaction using the node internal API ")
        self.api = api
        self.native_transactions = native

    @staticmethod
    def compute_tx_hash(signed_tx: str) -> str:
        """
        Generate the hash from a signed and encoded transaction
        :param signed_tx: an encoded signed transaction
        """
        signed = decode(signed_tx)
        return hash_encode(idf.TRANSACTION_HASH, signed)

    #cmk added
    def tx_channel_close_solo(self, account_id : str,
                              state : Union[str, bytes],
                              poi : str,
                              channel_id : str,
                              ttl : int,
                              fee : int,
                              nonce : int):

        if self.native_transactions:
            if isinstance(state, str):
                state = decode(state)

            tx = [
                _int(OBJECT_TAG_CHANNEL_CLOSE_SOLO_TRANSACTION),
                _int(VSN),
                _id(ID_TAG_CHANNEL, channel_id),
                _id(ID_TAG_ACCOUNT, account_id), #from_id
                _binary(state), #payload
                _binary(decode(poi)),
                _int(ttl),
                _int(fee),
                _int(nonce)
            ]
            tx = encode_rlp("tx", tx)
            return tx
        else:
            if not isinstance(state, str):
                state = encode("tx", state)

            tx = self.api.post_channel_close_solo(body={
                "from_id": account_id,
                "payload": state,
                "fee": fee,
                "poi": poi,
                "channel_id": channel_id,
                "ttl": ttl,
                "nonce": nonce
            }).tx

            #compensate bug in api
            tx = decode_rlp(tx)
            tx[4] = decode(tx[4].decode("UTF-8")) #the field 4, payload is a string such as "tx_...." encoding the payload when it should be a binary()
            tx = encode_rlp("tx",tx)
            return tx

    #cmk added
    def tx_channel_settle(self,
                          channel_id: str,
                          account_id : str,
                          initiator_amount_final : int,
                          responder_amount_final : int,
                          ttl : int,
                          fee : int,
                          nonce : int):

        if self.native_transactions:
            tx = [
                _int(OBJECT_TAG_CHANNEL_SETTLE_TRANSACTION),
                _int(VSN),
                _id(ID_TAG_CHANNEL, channel_id),
                _id(ID_TAG_ACCOUNT, account_id), #from_id
                _int(initiator_amount_final),
                _int(responder_amount_final),
                _int(ttl),
                _int(fee),
                _int(nonce)
            ]
            return encode_rlp("tx", tx)
        else:
            tx = self.api.post_channel_settle(body={
                "from_id": account_id,
                "responder_amount_final": responder_amount_final,
                "fee": fee,
                "initiator_amount_final": initiator_amount_final,
                "channel_id": channel_id,
                "ttl": ttl,
                "nonce": nonce
            }).tx
            return tx

    def tx_channel_close_mutual(self,
                                account_id : str,
                                channel_id : str,
                                initiator_amount_final : int,
                                responder_amount_final : int,
                                ttl : int,
                                fee : int,
                                nonce : int):
        if self.native_transactions:
            tx = [
                _int(OBJECT_TAG_CHANNEL_CLOSE_MUTUAL_TRANSACTION),
                _int(VSN),
                _id(ID_TAG_CHANNEL, channel_id),
                _id(ID_TAG_ACCOUNT, account_id),
                _int(initiator_amount_final),
                _int(responder_amount_final),
                _int(ttl),
                _int(fee),
                _int(nonce)
            ]
            return encode_rlp("tx", tx)
        else:
            tx = self.api.post_channel_close_mutual(body={
                "from_id": account_id,
                "responder_amount_final": initiator_amount_final,
                "fee": fee,
                "initiator_amount_final": responder_amount_final,
                "channel_id": channel_id,
                "ttl": ttl,
                "nonce" : nonce
            }).tx
        return tx

    #cmk added
    def tx_channel_slash(self,
                         channel_id : str,
                         account_id : str,
                         state : Union[str, bytes],
                         poi : str,
                         ttl : int,
                         fee : int,
                         nonce : int):
        if self.native_transactions:
            if isinstance(state, str):
                state = decode(state)

            tx = [
                _int(OBJECT_TAG_CHANNEL_SLASH_TRANSACTION),
                _int(VSN),
                _id(ID_TAG_CHANNEL, channel_id),
                _id(ID_TAG_ACCOUNT, account_id), #from_id
                _binary(state), #payload
                _binary(decode(poi)),
                _int(ttl),
                _int(fee),
                _int(nonce)
            ]
            return encode_rlp("tx", tx)
        else:
            if not isinstance(state, str):
                state = encode("tx", state)

            tx = self.api.post_channel_slash(body={
                "from_id" : account_id,
                "channel_id" : channel_id,
                "payload" : state,
                "poi" : poi,
                "ttl" : ttl,
                "fee" : fee,
                "nonce" : nonce
            }).tx

            return tx

    #cmk added - untested - speculative
    def tx_channel_solo_force_progress(self,
                                  channel_id : str,
                                  account_id : str,
                                  state : Union[str, bytes],
                                  new_round : int,
                                  contract_call_update : str,
                                  new_state_hash : str,
                                  offchain_trees : str,
                                  ttl : int,
                                  fee : int,
                                  nonce : int):
        if self.native_transactions:
            if isinstance(state, str):
                state = decode(state)

            tx = [ _int(OBJECT_TAG_CHANNEL_FORCE_PROGRESS_TRANSACTION),
                   _int(VSN),
                   _id(ID_TAG_CHANNEL, channel_id),
                   _id(ID_TAG_ACCOUNT, account_id), #from_id
                   _binary(state), #payload
                   _int(new_round), #round
                   _binary(decode(contract_call_update)),
                   _binary(decode(new_state_hash)),
                   _binary(decode(offchain_trees)), #actually trees() format and not binary
                   _int(ttl),
                   _int(fee),
                   _int(nonce)
                   ]
            return tx
        else:
            raise NotImplementedError("This version of SDK assumes Epoch 1.1.1, whose REST API does not implement " +
                                      "creation of Channel Force Progress Transactions")

    def tx_spend(self, account_id, recipient_id, amount, payload, fee, ttl, nonce)-> str:
        """
        create a spend transaction
        :param account_id: the public key of the sender
        :param recipient_id: the public key of the recipient
        :param amount: the amount to send
        :param payload: the payload associated with the data
        :param fee: the fee for the transaction
        :param ttl: the absolute ttl of the transaction
        :param nonce: the nonce of the transaction
        """
        # compute the absolute ttl and the nonce
        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_SPEND_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _id(idf.ID_TAG_ACCOUNT, recipient_id),
                _int(amount),
                _int(fee),
                _int(ttl),
                _int(nonce),
                _binary(payload)
            ]
            tx = encode_rlp(idf.TRANSACTION, tx)
            return tx

        # use internal endpoints transaction
        body = {
            "recipient_id": recipient_id,
            "amount": amount,
            "fee":  fee,
            "sender_id": account_id,
            "payload": payload,
            "ttl": ttl,
            "nonce": nonce,
        }
        return self.api.post_spend(body=body).tx

    # NAMING #

    def tx_name_preclaim(self, account_id, commitment_id, fee, ttl, nonce)-> str:
        """
        create a preclaim transaction
        :param account_id: the account registering the name
        :param commitment_id: the commitment id
        :param fee:  the fee for the transaction
        :param ttl:  the ttl for the transaction
        :param nonce: the nonce of the account for the transaction
        """
        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_NAME_SERVICE_PRECLAIM_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                _id(idf.ID_TAG_COMMITMENT, commitment_id),
                _int(fee),
                _int(ttl)
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            commitment_id=commitment_id,
            fee=fee,
            account_id=account_id,
            ttl=ttl,
            nonce=nonce
        )
        return self.api.post_name_preclaim(body=body).tx

    def tx_name_claim(self, account_id, name, name_salt, fee, ttl, nonce)-> str:
        """
        create a preclaim transaction
        :param account_id: the account registering the name
        :param commitment_id: the commitment id
        :param commitment_hash:  the commitment hash
        :param fee:  the fee for the transaction
        :param ttl:  the ttl for the transaction
        :param nonce: the nonce of the account for the transaction
        """
        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_NAME_SERVICE_CLAIM_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                decode(name),
                _binary(name_salt),
                _int(fee),
                _int(ttl)
            ]
            tx = encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            account_id=account_id,
            name=name,
            name_salt=name_salt,
            fee=fee,
            ttl=ttl,
            nonce=nonce
        )
        return self.api.post_name_claim(body=body).tx

    def tx_name_update(self, account_id, name_id, pointers, name_ttl, client_ttl, fee, ttl, nonce)-> str:
        """
        create an update transaction
        :param account_id: the account updating the name
        :param name_id: the name id
        :param pointers:  the pointers to update to
        :param name_ttl:  the ttl for the name registration
        :param client_ttl:  the ttl for client to cache the name
        :param fee: the transaction fee
        :param ttl: the ttl of the transaction
        :param nonce: the nonce of the account for the transaction
        """
        if self.native_transactions:
            # TODO: verify supported keys for name updates
            def pointer_tag(pointer):
                return {
                    "account_pubkey": idf.ID_TAG_ACCOUNT,
                    "oracle_pubkey": idf.ID_TAG_ORACLE,
                    "contract_pubkey": idf.ID_TAG_CONTRACT,
                    "channel_pubkey": idf.ID_TAG_CHANNEL
                }.get(pointer.get("key"))
            ptrs = [[_binary(p.get("key")), _id(idf.pointer_tag(p), p.get("id"))] for p in pointers]
            # build tx
            tx = [
                _int(idf.OBJECT_TAG_NAME_SERVICE_UPDATE_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                _id(idf.ID_TAG_NAME, name_id),
                _int(name_ttl),
                ptrs,
                _int(client_ttl),
                _int(fee),
                _int(ttl)
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            account_id=account_id,
            name_id=name_id,
            client_ttl=client_ttl,
            name_ttl=name_ttl,
            pointers=pointers,
            ttl=ttl,
            fee=fee,
            nonce=nonce
        )
        return self.api.post_name_update(body=body).tx

    def tx_name_transfer(self, account_id, name_id, recipient_id, fee, ttl, nonce)-> str:
        """
        create a transfer transaction
        :param account_id: the account transferring the name
        :param name_id: the name to transfer
        :param recipient_id: the address of the account to transfer the name to
        :param fee: the transaction fee
        :param ttl: the ttl of the transaction
        :param nonce: the nonce of the account for the transaction
        """
        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_NAME_SERVICE_TRANSFER_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                _id(idf.ID_TAG_NAME, name_id),
                _id(idf.ID_TAG_ACCOUNT, recipient_id),
                _int(fee),
                _int(ttl),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            account_id=account_id,
            name_id=name_id,
            recipient_id=recipient_id,
            ttl=ttl,
            fee=fee,
            nonce=nonce
        )
        return self.api.post_name_transfer(body=body).tx

    def tx_name_revoke(self, account_id, name_id, fee, ttl, nonce)-> str:
        """
        create a revoke transaction
        :param account_id: the account revoking the name
        :param name_id: the name to revoke
        :param fee: the transaction fee
        :param ttl: the ttl of the transaction
        :param nonce: the nonce of the account for the transaction
        """

        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_NAME_SERVICE_REVOKE_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                _id(idf.ID_TAG_NAME, name_id),
                _int(fee),
                _int(ttl),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            account_id=account_id,
            name_id=name_id,
            ttl=ttl,
            fee=fee,
            nonce=nonce
        )
        return self.api.post_name_revoke(body=body).tx

    # CONTRACTS

    def tx_contract_create(self, account_id, code, call_data, amount, deposit, gas, gas_price, vm_version, fee, ttl, nonce)-> str:
        """
        Create a contract transaction
        :param account_id: the account creating the contract
        :param code: the binary code of the contract
        :param call_data: the call data for the contract
        :param amount: TODO: add definition
        :param deposit: TODO: add definition
        :param gas: TODO: add definition
        :param gas_price: TODO: add definition
        :param vm_version: TODO: add definition
        :param fee: the transaction fee
        :param ttl: the ttl of the transaction
        :param nonce: the nonce of the account for the transaction
        """

        if self.native_transactions:
            tx = [
                _id(idf.account_id),
                _int(nonce),
                _binary(code),
                _int(vm_version),
                _int(fee),
                _int(ttl),
                _int(deposit),
                _int(amount),
                _int(gas),
                _int(gas_price),
                _binary(call_data),
            ]
            return encode_rlp(idf.TRANSACTION, tx), contract_id(idf.account_id, nonce)
        # use internal endpoints transaction
        body = dict(
            owner_id=account_id,
            amount=amount,
            deposit=deposit,
            fee=fee,
            gas=gas,
            gas_price=gas_price,
            vm_version=vm_version,
            call_data=call_data,
            code=code,
            ttl=ttl,
            nonce=nonce
        )
        tx = self.api.post_contract_create(body=body)
        return tx.tx, tx.contract_id

    def tx_contract_call(self, account_id, contract_id, call_data, function, arg, amount, gas, gas_price, vm_version, fee, ttl, nonce)-> str:
        """
        Create a contract call
        :param account_id: the account creating the contract
        :param contract_id: the contract to call
        :param call_data: the call data for the contract
        :param function: the function to execute
        :param arg: the function arguments
        :param amount: TODO: add definition
        :param gas: TODO: add definition
        :param gas_price: TODO: add definition
        :param vm_version: TODO: add definition
        :param fee: the transaction fee
        :param ttl: the ttl of the transaction
        :param nonce: the nonce of the account for the transaction
        """
        if self.native_transactions:
            tx = [
                _id(idf.account_id),
                _int(nonce),
                _id(idf.contract_id),
                _int(vm_version),
                _int(fee),
                _int(ttl),
                _int(amount),
                _int(gas),
                _int(gas_price),
                _binary(call_data),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            call_data=call_data,
            caller_id=account_id,
            contract_id=contract_id,
            amount=amount,
            fee=fee,
            gas=gas,
            gas_price=gas_price,
            vm_version=vm_version,
            ttl=ttl,
            nonce=nonce
        )
        return self.api.post_contract_call(body=body).tx

    # ORACLES

    def tx_oracle_register(self, account_id,
                           query_format, response_format,
                           query_fee, ttl_type, ttl_value, vm_version,
                           fee, ttl, nonce)-> str:
        """
        Create a register oracle transaction
        """

        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_ORACLE_REGISTER_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, account_id),
                _int(nonce),
                _binary(query_format),
                _binary(response_format),
                _int(query_fee),
                _int(0 if ttl_type == ORACLE_DEFAULT_TTL_TYPE_DELTA else 1),
                _int(ttl_value),
                _int(fee),
                _int(ttl),
                _int(vm_version),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            account_id=account_id,
            query_format=query_format,
            response_format=response_format,
            query_fee=query_fee,
            oracle_ttl=dict(
                type=ttl_type,
                value=ttl_value),
            vm_version=vm_version,
            fee=fee,
            ttl=ttl,
            nonce=nonce
        )
        tx = self.api.post_oracle_register(body=body)
        return tx.tx

    def tx_oracle_query(self, oracle_id, sender_id, query,
                        query_fee, query_ttl_type, query_ttl_value,
                        response_ttl_type, response_ttl_value,
                        fee, ttl, nonce)-> str:
        """
        Create a oracle query transaction
        """

        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_ORACLE_QUERY_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ACCOUNT, sender_id),
                _int(nonce),
                _id(idf.ID_TAG_ORACLE, oracle_id),
                _binary(query),
                _int(query_fee),
                _int(0 if query_ttl_type == ORACLE_DEFAULT_TTL_TYPE_DELTA else 1),
                _int(query_ttl_value),
                _int(0 if response_ttl_type == ORACLE_DEFAULT_TTL_TYPE_DELTA else 1),
                _int(response_ttl_value),
                _int(fee),
                _int(ttl),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            sender_id=sender_id,
            oracle_id=oracle_id,
            response_ttl=dict(
                type=response_ttl_type,
                value=response_ttl_value
            ),
            query=query,
            query_ttl=dict(
                type=query_ttl_type,
                value=query_ttl_value
            ),
            fee=fee,
            query_fee=query_fee,
            ttl=ttl,
            nonce=nonce,
        )
        tx = self.api.post_oracle_query(body=body)
        return tx.tx

    def tx_oracle_respond(self, oracle_id, query_id, response,
                          response_ttl_type, response_ttl_value,
                          fee, ttl, nonce)-> str:
        """
        Create a oracle response transaction
        """

        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_ORACLE_RESPONSE_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ORACLE, oracle_id),
                _int(nonce),
                _binary(query_id),
                _binary(response),
                _int(0 if response_ttl_type == ORACLE_DEFAULT_TTL_TYPE_DELTA else 1),
                _int(response_ttl_value),
                _int(fee),
                _int(ttl),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            response_ttl=dict(
                type=response_ttl_type,
                value=response_ttl_value
            ),
            oracle_id=oracle_id,
            query_id=query_id,
            response=response,
            fee=fee,
            ttl=ttl,
            nonce=nonce,
        )
        tx = self.api.post_oracle_respond(body=body)
        return tx.tx

    def tx_oracle_extend(self, oracle_id,
                         ttl_type, ttl_value,
                         fee, ttl, nonce)-> str:
        """
        Create a oracle extends transaction
        """

        if self.native_transactions:
            tx = [
                _int(idf.OBJECT_TAG_ORACLE_EXTEND_TRANSACTION),
                _int(idf.VSN),
                _id(idf.ID_TAG_ORACLE, oracle_id),
                _int(nonce),
                _int(0 if ttl_type == ORACLE_DEFAULT_TTL_TYPE_DELTA else 1),
                _int(ttl_value),
                _int(fee),
                _int(ttl),
            ]
            return encode_rlp(idf.TRANSACTION, tx)
        # use internal endpoints transaction
        body = dict(
            oracle_id=oracle_id,
            oracle_ttl=dict(
                type=ttl_type,
                value=ttl_value
            ),
            fee=fee,
            ttl=ttl,
            nonce=nonce,
        )
        tx = self.api.post_oracle_extend(body=body)
        return tx.tx
