/**
 *  @copyright defined in eos/LICENSE.txt
 */

#include <rem.auth/rem.auth.hpp>
#include <rem.system/rem.system.hpp>
#include <rem.oracle/rem.oracle.hpp>
#include <rem.token/rem.token.hpp>

namespace eosio {

   using eosiosystem::system_contract;

   static inline vector<char> join( vector<vector<char>>&& vec, string delim = "*" )
   {
      vector<char> result;
      std::size_t vec_size = vec.size();

      std::size_t delim_index = vec_size - 1;
      for (std::size_t i=0; i < vec_size; ++i) {
         result.insert(result.end(), vec.at(i).begin(), vec.at(i).end());

         if (delim_index - i > 0) {
            result.insert(result.end(), delim.begin(), delim.end());
         }
      }

      return result;
   }

   static inline vector<char> get_pub_key_data(const public_key &key)
   {
      vector<char> data_with_algorithm = pack<public_key>(key);

      // skip the first byte which is the public key type (R1 (0x01) or K1 (0x02))
      vector<char> data(data_with_algorithm.begin() + 1, data_with_algorithm.end());
      return data;
   }

   void auth::addkeyacc(const name &account, const public_key &pub_key, const signature &signed_by_pub_key,
                        const asset &price_limit, const name &payer)
   {
      name payer_name = bool(payer) ? payer : account;
      require_auth(account);
      require_auth(payer_name);

      string account_str = account.to_string();
      string payer_str = payer.to_string();
      vector<char> account_data(account_str.begin(), account_str.end());
      vector<char> pub_key_data = get_pub_key_data(pub_key);
      vector<char> payer_data(payer_str.begin(), payer_str.end());

      vector<char> payload = join({ account_data, pub_key_data, payer_data });
      checksum256 digest = sha256(payload.data(), payload.size());
      assert_recover_key(digest, signed_by_pub_key, pub_key);

      authkeys_tbl.emplace(get_self(), [&](auto &k) {
         k.key                = authkeys_tbl.available_primary_key();
         k.owner              = account;
         k.pub_key            = pub_key;
         k.not_valid_before   = current_time_point();
         k.not_valid_after    = current_time_point() + key_lifetime;
         k.revoked_at         = 0; // if not revoked == 0
      });

      sub_storage_fee(payer_name, price_limit);
      cleanupkeys();
   }

   void auth::execaction(const name &account, action& act, const block_timestamp &action_timestamp,
                         const public_key &pub_key, const signature &action_data_signature)
   {
      auto auths_level = act.authorization;
      auto permission  = auths_level.front();
      time_point action_timepoint = action_timestamp.to_time_point();
      auto action_expiration_delta = current_time_point().time_since_epoch() - action_sig_expiration_time.time_since_epoch();

      check(auths_level.size() == 1, "action authorization should contain one permission");
      check(permission.actor == account, "missing authority of " + account.to_string());
      check(time_point(action_expiration_delta) < action_timepoint, "action timestamp expired");

      vector<char> account_data = pack(account);
      vector<char> action_data = pack(act);
      vector<char> action_timestamp_data = pack(action_timestamp);
      vector<char> pub_key_data = get_pub_key_data(pub_key);

      vector<char> payload = join({ account_data, action_data, action_timestamp_data, pub_key_data });
      checksum256 digest = sha256(payload.data(), payload.size());

      assert_recover_key(digest, action_data_signature, pub_key);
      require_app_auth(account, pub_key);

      auto execaction_idx = execaction_tbl.get_index<"byhash"_n>();
      auto action_it = execaction_idx.find(execaction_data::get_action_hash(digest));
      check(action_it == execaction_idx.end(), "the action has already been executed");

      execaction_tbl.emplace(get_self(), [&](auto &a) {
         a.key              = execaction_tbl.available_primary_key();
         a.action_id        = digest;
         a.action_timestamp = action_timestamp;
      });

      act.send();
      cleanup_actions();
   }

   void auth::addkeyapp(const name &account, const public_key &new_pub_key, const signature &signed_by_new_pub_key,
                        const public_key &pub_key, const signature &signed_by_pub_key, const asset &price_limit,
                        const name &payer)
   {
      bool is_payer = bool(payer);
      name payer_name = is_payer ? payer : account;
      if (is_payer) { require_auth(payer_name); }

      string account_str = account.to_string();
      string payer_str = payer.to_string();
      vector<char> account_data(account_str.begin(), account_str.end());
      vector<char> new_pub_key_data = get_pub_key_data(new_pub_key);
      vector<char> pub_key_data = get_pub_key_data(pub_key);
      vector<char> payer_data(payer_str.begin(), payer_str.end());

      vector<char> payload = join({ account_data, new_pub_key_data, pub_key_data, payer_data });
      checksum256 digest = sha256(payload.data(), payload.size());

      public_key expected_new_pub_key = recover_key(digest, signed_by_new_pub_key);
      public_key expected_pub_key = recover_key(digest, signed_by_pub_key);

      check(expected_new_pub_key == new_pub_key, "expected key different than recovered new application key");
      check(expected_pub_key == pub_key, "expected key different than recovered application key");
      require_app_auth(account, pub_key);

      authkeys_tbl.emplace(get_self(), [&](auto &k) {
         k.key              = authkeys_tbl.available_primary_key();
         k.owner            = account;
         k.pub_key          = new_pub_key;
         k.not_valid_before = current_time_point();
         k.not_valid_after  = current_time_point() + key_lifetime;
         k.revoked_at       = 0; // if not revoked == 0
      });

      sub_storage_fee(payer_name, price_limit);
      cleanupkeys();
   }

   void auth::replacekey(const name &account, const public_key &new_pub_key, const signature &signed_by_new_pub_key,
                         const public_key &pub_key, const signature &signed_by_pub_key, const asset &price_limit,
                         const name &payer)
   {
      bool is_payer = bool(payer);
      name payer_name = is_payer ? payer : account;
      if (is_payer) { require_auth(payer_name); }

      string account_str = account.to_string();
      string payer_str = payer.to_string();
      vector<char> account_data(account_str.begin(), account_str.end());
      vector<char> new_pub_key_data = get_pub_key_data(new_pub_key);
      vector<char> pub_key_data = get_pub_key_data(pub_key);
      vector<char> payer_data(payer_str.begin(), payer_str.end());

      vector<char> payload = join({ account_data, new_pub_key_data, pub_key_data, payer_data });
      checksum256 digest = sha256(payload.data(), payload.size());

      public_key expected_new_pub_key = recover_key(digest, signed_by_new_pub_key);
      public_key expected_pub_key = recover_key(digest, signed_by_pub_key);

      check(expected_new_pub_key == new_pub_key, "expected key different than recovered new application key");
      check(expected_pub_key == pub_key, "expected key different than recovered application key");

      auto authkeys_idx = authkeys_tbl.get_index<"bypubkey"_n>();
      auto it = authkeys_idx.find(authkeys::get_pub_key_hash(pub_key));

      time_point ct = current_time_point();
      bool is_before_time_valid = ct > it->not_valid_before.to_time_point();
      bool is_after_time_valid = ct < it->not_valid_after.to_time_point() + key_replacement_timedelta;

      check(it != authkeys_idx.end(), "account has no active application keys");
      check(it->owner == account, "owner of the key does not match the account");
      check(is_before_time_valid && is_after_time_valid, "key expired");
      check(!it->revoked_at, "key expired");

      authkeys_tbl.modify(*it, get_self(), [&](auto &r) {
         r.revoked_at = ct.sec_since_epoch();
      });

      authkeys_tbl.emplace(get_self(), [&](auto &k) {
         k.key              = authkeys_tbl.available_primary_key();
         k.owner            = account;
         k.pub_key          = new_pub_key;
         k.not_valid_before = current_time_point();
         k.not_valid_after  = current_time_point() + key_lifetime;
         k.revoked_at       = 0; // if not revoked == 0
      });

      sub_storage_fee(payer_name, price_limit);
      cleanupkeys();
   }

   auto auth::find_active_appkey(const name &account, const public_key &key)
   {
      auto authkeys_idx = authkeys_tbl.get_index<"byname"_n>();
      auto it = authkeys_idx.find(account.value);

      for(; it != authkeys_idx.end(); ++it) {
         auto ct = current_time_point();

         bool is_before_time_valid = ct > it->not_valid_before.to_time_point();
         bool is_after_time_valid = ct < it->not_valid_after.to_time_point();
         bool is_revoked = it->revoked_at;

         if (!is_before_time_valid || !is_after_time_valid || is_revoked) {
            continue;
         } else if (it->pub_key == key) {
            break;
         }
      }
      return it;
   }

   void auth::revokeacc(const name &account, const public_key &revoke_pub_key)
   {
      require_auth(account);
      require_app_auth(account, revoke_pub_key);

      auto it = find_active_appkey(account, revoke_pub_key);

      time_point ct = current_time_point();
      authkeys_tbl.modify(*it, get_self(), [&](auto &r) {
         r.revoked_at = ct.sec_since_epoch();
      });
   }

   void auth::revokeapp(const name &account, const public_key &revoke_pub_key,
                        const public_key &pub_key, const signature &signed_by_pub_key)
   {
      string account_str = account.to_string();
      vector<char> account_data(account_str.begin(), account_str.end());
      vector<char> revoke_pub_key_data = get_pub_key_data(revoke_pub_key);
      vector<char> pub_key_data = get_pub_key_data(pub_key);

      vector<char> payload = join({ account_data, revoke_pub_key_data, pub_key_data });
      checksum256 digest = sha256(payload.data(), payload.size());

      public_key expected_pub_key = recover_key(digest, signed_by_pub_key);
      check(expected_pub_key == pub_key, "expected key different than recovered application key");
      require_app_auth(account, revoke_pub_key);
      require_app_auth(account, pub_key);

      auto it = find_active_appkey(account, revoke_pub_key);

      time_point ct = current_time_point();
      authkeys_tbl.modify(*it, get_self(), [&](auto &r) {
         r.revoked_at = ct.sec_since_epoch();
      });
   }

   void auth::transfer(const name &from, const name &to, const asset &quantity, const string &memo,
                       const public_key &pub_key, const signature &signed_by_pub_key)
   {
      string from_str = from.to_string();
      string to_str = to.to_string();
      string quantity_str = quantity.to_string();
      vector<char> pub_key_data = get_pub_key_data(pub_key);

      vector<char> payload = join({
         vector<char>(from_str.begin(), from_str.end()),
         vector<char>(to_str.begin(), to_str.end()),
         vector<char>(quantity_str.begin(), quantity_str.end()),
         vector<char>(memo.begin(), memo.end()),
         pub_key_data
      });
      checksum256 digest = sha256(payload.data(), payload.size());

      public_key expected_pub_key = recover_key(digest, signed_by_pub_key);

      check(expected_pub_key == pub_key, "expected key different than recovered application key");
      require_app_auth(from, pub_key);

      transfer_tokens(from, to, quantity, memo);
   }

   void auth::buyauth(const name &account, const asset &quantity, const double &max_price)
   {
      require_auth(account);
      check(quantity.is_valid(), "invalid quantity");
      check(quantity.amount > 0, "quantity should be a positive value");
      check(max_price > 0, "maximum price should be a positive value");
      check(quantity.symbol == system_contract::auth_symbol, "symbol precision mismatch");

      remoracle::remprice_idx remprice_table(system_contract::oracle_account, system_contract::oracle_account.value);
      auto remusd_it = remprice_table.find(system_contract::rem_usd_pair.value);
      check(remusd_it != remprice_table.end(), "pair does not exist");

      double remusd_price = remusd_it->price;
      double account_discount = get_account_discount(account);
      check(max_price > remusd_price, "currently REM/USD price is above maximum price");

      asset purchase_fee = get_purchase_fee(quantity);
      purchase_fee.amount *= account_discount;

      token::issue_action issue(system_contract::token_account, { get_self(), system_contract::active_permission });

      transfer_tokens(account, get_self(), purchase_fee, "AUTH credits purchase fee");
      issue.send(get_self(), quantity, "buying an AUTH credits");
      transfer_tokens(get_self(), account, quantity, "buying an AUTH credits");
   }

   void auth::cleanupkeys() {
      const uint8_t max_cleanup_depth = 10;
      size_t i = 0;
      for (auto _table_itr = authkeys_tbl.begin(); _table_itr != authkeys_tbl.end();) {
         time_point not_valid_after = _table_itr->not_valid_after.to_time_point();
         bool not_expired = time_point_sec(current_time_point()) <= not_valid_after + key_cleanup_time;

         if (not_expired || i >= max_cleanup_depth) {
            break;
         } else {
            _table_itr = authkeys_tbl.erase(_table_itr);
            ++i;
         }
      }
   }

   void auth::cleanup_actions() {
      const uint8_t max_cleanup_depth = 10;
      size_t i = 0;
      for (auto _table_itr = execaction_tbl.begin(); _table_itr != execaction_tbl.end();) {
         time_point action_exec_time = _table_itr->action_timestamp.to_time_point();
         bool not_expired = time_point_sec(current_time_point()) <= action_exec_time + action_expiration_time;

         if (not_expired || i >= max_cleanup_depth) {
            break;
         } else {
            _table_itr = execaction_tbl.erase(_table_itr);
            ++i;
         }
      }
   }

   void auth::sub_storage_fee(const name &account, const asset &price_limit)
   {
      bool is_pay_by_auth = (price_limit.symbol == system_contract::auth_symbol);
      bool is_pay_by_rem  = (price_limit.symbol == system_contract::get_core_symbol());

      check(is_pay_by_rem || is_pay_by_auth, "unavailable payment method");
      check(price_limit.is_valid(), "invalid price limit");
      check(price_limit.amount > 0, "price limit should be a positive value");

      asset auth_credit_supply = token::get_supply(system_contract::token_account, system_contract::auth_symbol.code());
      asset key_storage_fee_in_auth = asset(key_storage_fee, system_contract::auth_symbol);
      asset rem_balance = get_balance(system_contract::token_account, get_self(), system_contract::get_core_symbol());

      if (is_pay_by_rem) {
         double account_discount = get_account_discount(account);
         asset purchase_fee = get_purchase_fee(key_storage_fee_in_auth);
         purchase_fee.amount *= account_discount;
         check(purchase_fee < price_limit, "currently REM/USD price is above price limit");

         transfer_tokens(account, get_self(), purchase_fee, "AUTH credits purchase fee");

         auth_credit_supply += key_storage_fee_in_auth;
         rem_balance += purchase_fee;
      } else {
         check(auth_credit_supply.amount > 0, "overdrawn balance");
         transfer_tokens(account, get_self(), key_storage_fee_in_auth, "AUTH credits purchase fee");

         token::retire_action retire(system_contract::token_account, { get_self(), system_contract::active_permission });
         retire.send(key_storage_fee_in_auth, "the use of AUTH credit to store a key");
      }

      double reward_amount = rem_balance.amount / double(auth_credit_supply.amount);

      system_contract::torewards_action torewards(system_account, { get_self(), system_contract::active_permission });
      torewards.send(get_self(), asset{static_cast<int64_t>(reward_amount * key_storage_fee_in_auth.amount), system_contract::get_core_symbol()});
   }

   double auth::get_account_discount(const name &account) const
   {
      const double default_account_discount = 1;

      attribute_info_table attributes_info(get_self(), get_self().value);
      if (attributes_info.begin() == attributes_info.end()) {
         return default_account_discount;
      }

      vector<char> data;
      for (auto it = attributes_info.begin(); it != attributes_info.end(); ++it) {
         attributes_table attributes(get_self(), it->attribute_name.value);
         auto idx = attributes.get_index<"reciss"_n>();
         auto attr_it = idx.find( attribute_data::combine_receiver_issuer(account, get_self()) );
         if (attr_it == idx.end() || !it->valid) {
            continue;
         }
         data = attr_it->attribute.data;
      }

      if (!data.empty()) {
         double account_discount = unpack<double>(data);
         check( account_discount >= 0 && account_discount <= 1, "attribute value error");

         return account_discount;
      }
      return default_account_discount;
   }

   void auth::require_app_auth(const name &account, const public_key &pub_key)
   {
      auto authkeys_idx = authkeys_tbl.get_index<"byname"_n>();
      auto it = authkeys_idx.find(account.value);

      check(it != authkeys_idx.end(), "account has no linked application keys");

      it = find_active_appkey(account, pub_key);
      check(it != authkeys_idx.end(), "account has no active application keys");
   }

   asset auth::get_balance(const name& token_contract_account, const name& owner, const symbol& sym)
   {
      accounts accountstable(token_contract_account, owner.value);
      const auto it = accountstable.find(sym.code().raw());

      asset account_balance = (it == accountstable.end()) ? asset{0, sym} : it->balance;
      return account_balance;
   }

   asset auth::get_purchase_fee(const asset &quantity_auth)
   {
      remoracle::remprice_idx remprice_table(system_contract::oracle_account, system_contract::oracle_account.value);
      auto remusd_it = remprice_table.find(system_contract::rem_usd_pair.value);
      check(remusd_it != remprice_table.end(), "pair does not exist");

      double remusd_price = remusd_it->price;
      int64_t price_per_auth = 1 / remusd_price;

      check(price_per_auth > 0, "invalid REM/USD price");

      asset purchase_fee =  asset( quantity_auth.amount * price_per_auth, system_contract::get_core_symbol() );
      return purchase_fee;
   }

   void auth::transfer_tokens(const name &from, const name &to, const asset &quantity, const string &memo)
   {
      token::transfer_action transfer(system_contract::token_account, {from, system_contract::active_permission});
      transfer.send(from, to, quantity, memo);
   }
} /// namespace eosio
