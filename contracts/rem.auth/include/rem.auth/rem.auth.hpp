/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

#include <rem.attr/rem.attr.hpp>

namespace eosio {

   using std::string;
   using std::vector;

   /**
    * @defgroup eosioauth rem.auth
    * @ingroup eosiocontracts
    *
    * rem.auth contract
    *
    * @details rem.auth contract defines the structures and actions that allow users and contracts to add, store, revoke
    * public keys.
    * @{
    */
   class [[eosio::contract("rem.auth")]] auth : public attribute {
   public:

      auth(name receiver, name code,  datastream<const char*> ds)
      :attribute(receiver, code, ds),
      authkeys_tbl(get_self(), get_self().value),
      execaction_tbl(get_self(), get_self().value){};

      /**
       * Add new authentication key action.
       *
       * @details Add new authentication key by user account.
       *
       * @param account - the owner account to execute the addkeyacc action for,
       * @param pub_key - the public key that signed the payload,
       * @param signed_by_pub_key - the signature that was signed by pub_key,
       * @param price_limit - the maximum price which will be charged for storing the key can be in REM and AUTH,
       * @param payer - the account from which resources are debited.
       */
      [[eosio::action]]
      void addkeyacc(const name &account, const public_key &pub_key, const signature &signed_by_pub_key,
                     const asset &price_limit, const name &payer);

      /**
       * Add new authentication key action.
       *
       * @details Add new authentication key by using correspond to the account authentication key.
       *
       * @param account - the owner account to execute the addkeyapp action for,
       * @param new_pub_key - the public key that will be added,
       * @param signed_by_new_pub_key - the signature that was signed by new_pub_key,
       * @param pub_key - the public key which is tied to the corresponding account,
       * @param sign_by_key - the signature that was signed by pub_key,
       * @param price_limit - the maximum price which will be charged for storing the key can be in REM and AUTH,
       * @param payer - the account from which resources are debited.
       */
      [[eosio::action]]
      void addkeyapp(const name &account, const public_key &new_pub_key, const signature &signed_by_new_pub_key,
                     const public_key &pub_key, const signature &signed_by_pub_key, const asset &price_limit,
                     const name &payer);

      /**
       * Revoke active authentication key action.
       *
       * @details Revoke already added active authentication key by user account.
       *
       * @param account - the owner account to execute the revokeacc action for,
       * @param pub_key - the public key to be revoked on the corresponding account.
       */
      [[eosio::action]]
      void revokeacc(const name &account, const public_key &revoke_pub_key);

      /**
       * Revoke active authentication key action.
       *
       * @details Revoke already added active authentication key by using correspond to account authentication key.
       *
       * @param account - the owner account to execute the revokeapp action for,
       * @param revoke_pub_key - the public key to be revoked on the corresponding account,
       * @param pub_key - the public key which is tied to the corresponding account,
       * @param signed_by_pub_key - the signature that was signed by pub_key.
       */
      [[eosio::action]]
      void revokeapp(const name &account, const public_key &revoke_pub_key,
                     const public_key &pub_key, const signature &signed_by_pub_key);

      /**
       * Buy AUTH credits action.
       *
       * @details buy AUTH credit at a current REM-USD price indicated in the rem.orace contract.
       *
       * @param account - the account to transfer from,
       * @param quantity - the quantity of AUTH credits to be purchased,
       * @param max_price - the maximum price for one AUTH credit, that amount of REM tokens that can be debited
       * for one AUTH credit.
       */
      [[eosio::action]]
      void buyauth(const name &account, const asset &quantity, const double &max_price);


      /**
       * Execaction action.
       *
       * @details Allows `account` to execute action `act` that signed by stored in auth public key `pub_key`.
       *
       * @param account - the owner account to execute the execaction action for,
       * @param act - account action that will be executed,
       * @param pub_key - the public key which is tied to the corresponding account
       * @param action_data_signature - the signature that was signed by pub_key.
       */
      [[eosio::action]]
      void execaction(const name &account, action& act, const block_timestamp &action_timestamp,
                      const public_key &pub_key, const signature &action_data_signature);

      /**
       * Transfer action.
       *
       * @details Allows `from` account to transfer to `to` account the `quantity` tokens.
       * One account is debited and the other is credited with quantity tokens.
       *
       * @param from - the account to transfer from,
       * @param to - the account to be transferred to,
       * @param quantity - the quantity of tokens to be transferred,
       * @param memo - the memo string to accompany the transaction,
       * @param pub_key - the public key which is tied to the corresponding account,
       * @param signed_by_pub_key - the signature that was signed by pub_key,
       */
      [[eosio::action]]
      void transfer(const name &from, const name &to, const asset &quantity, const string &memo,
                    const public_key &pub_key, const signature &signed_by_pub_key);

      /**
       * Cleanup authkeys table action.
       *
       * @details Delete expired keys (keys for which not_valid_after plus expiration_time has passed).
       */
      [[eosio::action]]
      void cleanupkeys();


      /**
       * Empty action.
       *
       */
      [[eosio::action]]
      void empty();

      using addkeyacc_action = action_wrapper<"addkeyacc"_n, &auth::addkeyacc>;
      using addkeyapp_action = action_wrapper<"addkeyapp"_n, &auth::addkeyapp>;
      using revokeacc_action = action_wrapper<"revokeacc"_n, &auth::revokeacc>;
      using revokeapp_action = action_wrapper<"revokeapp"_n, &auth::revokeapp>;
      using buyauth_action   = action_wrapper<"buyauth"_n,     &auth::buyauth>;
      using transfer_action  = action_wrapper<"transfer"_n,   &auth::transfer>;
   private:
      static constexpr name system_account = "rem"_n;

      const time_point key_lifetime = time_point(days(360));
      const time_point key_cleanup_time = time_point(days(180)); // the time that should be passed after not_valid_after to delete key
      const time_point action_expiration_time = time_point(days(30));
      const time_point action_sig_expiration_time = time_point(hours(1));
      static constexpr int64_t key_storage_fee = 1'0000;

      enum class pub_key_algorithm : int8_t { ES256K1 = 0, ES256 };

      struct [[eosio::table]] authkeys {
         uint64_t             key;
         name                 owner;
         public_key           pub_key;
         block_timestamp      not_valid_before;
         block_timestamp      not_valid_after;
         uint32_t             revoked_at;

      static fixed_bytes<32> get_pub_key_hash(public_key key) {
         bool is_k1_type = std::get_if<0>(&key);
         auto key_data = is_k1_type ? std::get_if<0>(&key)->data() : std::get_if<1>(&key)->data();
         auto key_size = is_k1_type ? std::get_if<0>(&key)->size() : std::get_if<1>(&key)->size();

         checksum256 key_hash = sha256(key_data, key_size);
         const uint128_t *p128 = reinterpret_cast<const uint128_t *>(&key_hash);
         fixed_bytes<32> key_hash_bytes;
         key_hash_bytes.data()[0] = p128[0];
         key_hash_bytes.data()[1] = p128[1];
         return key_hash_bytes;
      }

      uint64_t primary_key()const          { return key;         }
      fixed_bytes<32> by_public_key()const { return get_pub_key_hash(pub_key); }
      uint64_t by_name()const              { return owner.value; }
      uint64_t by_not_valid_before()const  { return not_valid_before.to_time_point().elapsed.count(); }
      uint64_t by_not_valid_after()const   { return not_valid_after.to_time_point().elapsed.count(); }
      uint64_t by_revoked()const           { return revoked_at;  }

      EOSLIB_SERIALIZE( authkeys, (key)(owner)(pub_key)(not_valid_before)(not_valid_after)(revoked_at))
      };
      typedef multi_index<"authkeys"_n, authkeys,
            indexed_by<"bypubkey"_n,     const_mem_fun <authkeys, fixed_bytes<32>, &authkeys::by_public_key>>,
            indexed_by<"byname"_n,       const_mem_fun < authkeys, uint64_t, &authkeys::by_name>>,
            indexed_by<"bynotvalbfr"_n,  const_mem_fun <authkeys, uint64_t, &authkeys::by_not_valid_before>>,
            indexed_by<"bynotvalaftr"_n, const_mem_fun <authkeys, uint64_t, &authkeys::by_not_valid_after>>,
            indexed_by<"byrevoked"_n,    const_mem_fun <authkeys, uint64_t, &authkeys::by_revoked>>
            > authkeys_idx;

      authkeys_idx authkeys_tbl;

      struct [[eosio::table]] execaction_data {
         uint64_t          key;
         checksum256       action_id;
         block_timestamp   action_timestamp;

         uint64_t primary_key() const { return key; }

         fixed_bytes<32> by_action_id() const { return get_action_hash(action_id); }

         static fixed_bytes<32> get_action_hash(const checksum256 &hash) {
            const uint128_t *p128 = reinterpret_cast<const uint128_t *>(&hash);
            fixed_bytes<32> k;
            k.data()[0] = p128[0];
            k.data()[1] = p128[1];
            return k;
         }

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( execaction_data, (key)(action_id)(action_timestamp) )
      };

      typedef multi_index<"execactions"_n, execaction_data,
         indexed_by<"byhash"_n, const_mem_fun <execaction_data, fixed_bytes<32>, &execaction_data::by_action_id>>
         > execaction_index;
      execaction_index execaction_tbl;

      struct [[eosio::table]] account {
         asset    balance;

         uint64_t primary_key()const { return balance.symbol.code().raw(); }
      };
      typedef multi_index<"accounts"_n, account> accounts;

      void sub_storage_fee(const name &account, const asset &price_limit);
      void transfer_tokens(const name &from, const name &to, const asset &quantity, const string &memo);
      void to_rewards(const name& payer, const asset &quantity);

      auto find_active_appkey(const name &account, const public_key &key);
      void require_app_auth(const name &account, const public_key &key);

      asset get_balance(const name& token_contract_account, const name& owner, const symbol& sym);
      asset get_purchase_fee(const asset &quantity_auth);
      double get_account_discount(const name &account) const;

      void cleanup_actions();

      void check_permission(const name& issuer, const name& receiver, int32_t ptype) const;
      bool need_confirm(int32_t ptype) const;
   };
   /** @}*/ // end of @defgroup eosioauth rem.auth
} /// namespace eosio
