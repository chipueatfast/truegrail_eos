#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/transaction.hpp>
#include <eosio/multi_index.hpp>
#include <string>

namespace eosio {
    using std::string;

    class [[eosio::contract("truegrail_eos")]] truegrail_eos: public contract {
        public:
            truegrail_eos(name self, name receiver, datastream<const char*> ds): contract(self, receiver, ds) {
            };

            [[eosio::action]]
            bool checkcreator() {
                require_auth(get_self());
                return true;
            }

            [[eosio::action]]
            void clearusers() {
                require_auth(get_self());
                users storage(get_self(), get_self().value);
                auto it = storage.begin();
                while (it != storage.end()) {
                    it = storage.erase(it);
                };
            }

            [[eosio::action]]
            void clearsneak() {
                require_auth(get_self());
                sneakers storage(get_self(), get_self().value);
                auto it = storage.begin();
                while (it != storage.end()) {
                    it = storage.erase(it);
                };
            }

            [[eosio::action]]
            void eraseuser(uint64_t user_id) {
                require_auth(get_self());
                users storage(get_self(), get_self().value);
                auto existing = storage.find(user_id);
                check(existing != storage.end(), "Record does not exist");
                storage.erase(existing);
            }

            [[eosio::action]]
            void insertuser(uint64_t user_id, name eos_name, string user_info_hash, string role) {
                require_auth(get_self());
                users storage(get_self(), get_self().value);
                auto existing = storage.find(user_id);
                check(existing == storage.end(), "This credential has already been registered");
                storage.emplace(get_self(), [&](auto& row) {
                    row.id = user_id;
                    row.info_hash = user_info_hash;
                    row.role = role;
                    row.eos_name = eos_name;
                });
            }

            [[eosio::action]]
            void updateuser(name user, uint64_t user_id, string user_info_hash) {
                require_auth(user);
                users storage(get_self(), get_self().value);
                auto existing = storage.find(user_id);
                check(existing != storage.end(), "This user does not exist");
                check(user == existing->eos_name, "This is not the valid user");
                storage.modify(existing, get_self(), [&] (auto& row) {
                    row.info_hash = user_info_hash;
                });
            }

            [[eosio::action]]
            bool checkfactory(name factory, uint64_t factory_id) {
                require_auth(factory);
                users storage(get_self(), get_self().value);
                auto existing = storage.find(factory_id);
                check(existing != storage.end() && existing->role == "factory", "This is not a factory cred");
                return true;
            }

            [[eosio::action]]
            void issue(name factory, uint64_t factory_id, name toclaim, uint64_t sneaker_id, string sneaker_info_hash) {
                check(checkfactory(factory, factory_id), "You are not the factory");
                sneakers storage(get_self(), get_self().value);
                struct sneaker new_sneaker = {
                    .id = sneaker_id,
                    .info_hash = sneaker_info_hash,
                    .owner_id = 0,
                    .owner = toclaim,
                    .status = "new",
                };
                insert_history_trace(sneaker_id, toclaim, NULL, NULL, "issue");
                storage.emplace(get_self(), [&](auto& row) {
                    row = new_sneaker;
                });
            };

            [[eosio::action]]
            void transfer(uint64_t sneaker_id, uint64_t new_owner_id) {
                sneakers sneaker_storage(get_self(), get_self().value);
                auto existing_sneaker = sneaker_storage.find(sneaker_id);
                check(existing_sneaker != sneaker_storage.end(), "sneaker does not exist!");
                require_auth(existing_sneaker -> owner);
                users user_storage(get_self(), get_self().value);
                auto existing_owner = user_storage.find(new_owner_id);
                check(existing_owner != user_storage.end(), "new owner does not exist!");

                if (existing_sneaker->owner_id == 0) {
                    insert_history_trace(sneaker_id, existing_owner->eos_name, new_owner_id, NULL, "claim");
                } else {
                    insert_history_trace(sneaker_id, name(NULL), new_owner_id, existing_sneaker->owner_id, "resell");
                }

                sneaker_storage.modify(existing_sneaker, get_self(), [&] (auto& row) {
                    row.owner = existing_owner->eos_name;
                    row.owner_id = new_owner_id;
                    row.status = "not new";
                });
            }

            [[eosio::action]]
            void updatestatus(uint64_t sneaker_id, string status) {
                sneakers sneaker_storage(get_self(), get_self().value);
                auto existing_sneaker = sneaker_storage.find(sneaker_id);
                check(existing_sneaker != sneaker_storage.end(), "sneaker does not exist!");
                require_auth(existing_sneaker -> owner);
                sneaker_storage.modify(existing_sneaker, get_self(), [&] (auto& row) {
                    row.status = status;
                });
            }


            // insecure, for demo only
            [[eosio::action]]
            void markfraud(name factory, uint64_t factory_id, uint64_t sneaker_id) {
                check(checkfactory(factory, factory_id), "Account not granted permission");
                sneakers sneaker_storage(get_self(), get_self().value);
                auto existing_sneaker = sneaker_storage.find(sneaker_id);
                check(existing_sneaker -> status == "new", "Sneaker has already been in trading");
                sneaker_storage.modify(existing_sneaker, get_self(), [&] (auto& row) {
                    row.status = "stolen";
                });
            }


        private:

            checksum256 get_trx_id() {
                size_t size = transaction_size();
                char buf[size];
                size_t read = read_transaction( buf, size );
                check( size == read, "read_transaction failed");
                return sha256(buf, read);
            }

            void insert_history_trace(
                uint64_t sneaker_id,
                name claimacc, 
                uint64_t buyer_id, 
                uint64_t seller_id, 
                string type
            ) {
                histories storage(get_self(), get_self().value);
                storage.emplace(get_self(), [&](auto& row) {
                    row.id = storage.available_primary_key();
                    row.trx_id = get_trx_id();
                    row.sneaker_id = sneaker_id;
                    row.claim_account = claimacc;
                    row.buyer_id = buyer_id;
                    row.seller_id = seller_id;
                    row.transaction_type = type;
                });

            }

            struct [[eosio::table]] user {
                uint64_t id;
                name eos_name;
                string info_hash;
                string role;

                uint64_t primary_key()const {
                    return id;
                }
            };

            struct [[eosio::table]] sneaker {
                uint64_t id;
                string info_hash;
                uint64_t owner_id;
                name owner;
                string status;

                uint64_t primary_key()const {
                    return id;
                }

                uint64_t get_secondary_index() const { return owner_id;}
            };

            struct [[eosio::table]] history {
                uint64_t id;
                checksum256 trx_id;
                uint64_t sneaker_id;
                name claim_account;
                uint64_t buyer_id;
                uint64_t seller_id;
                string transaction_type;

                uint64_t primary_key() const {
                    return id;
                }
                checksum256 get_trx_id_index() const {
                    return trx_id;
                }
                uint64_t get_sneaker_id_index() const {
                    return sneaker_id;
                }
            };

            typedef multi_index<"users"_n, user> users;
            typedef multi_index<"sneakers"_n, sneaker,
                    indexed_by
                    <
                        "byownerid"_n,
                        const_mem_fun<sneaker, uint64_t, &sneaker::get_secondary_index>
                    >
                > sneakers;
            typedef multi_index<
                        "histories"_n,
                        history,
                        indexed_by
                        <
                            "bytrxid"_n,
                            const_mem_fun<history, checksum256, &history::get_trx_id_index>
                        >,
                        indexed_by
                        <
                            "bysneakerid"_n,
                            const_mem_fun<history, uint64_t, &history::get_sneaker_id_index>
                        >
                    > histories;
    };
}



