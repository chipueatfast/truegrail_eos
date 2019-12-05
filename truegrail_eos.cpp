#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
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
                users storage(get_self(), get_self().value);
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
                storage.emplace(get_self(), [&](auto& row) {
                    row = new_sneaker;
                });
            };


            // [[eosio::action]]
            // void transfer(uint64_t sneaker_id, uint64_t user_id, string user_info_hash) {
            //     require_auth(get_self());
            //     ownerships storage(get_self(), get_self().value);
            //     auto existing = storage.find(sneaker_id);
            //     check(existing != storage.end(), "sneaker does not exist!");
            //     storage.modify(existing, get_self(), [&] (auto& row) {
            //         row.sneaker = existing -> sneaker;
            //         struct user new_owner = {
            //             .id = user_id,
            //             .info_hash = user_info_hash,
            //         };
            //         row.owner = new_owner;
            //     });
            // }


        private:

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
            };

            struct [[eosio::table]] history {
                checksum256 tx_hash;

                checksum256 primary_key()const {
                    return tx_hash;
                }
            };

            struct [[eosio::table]] ownership {
                sneaker sneaker;
                user owner;

                uint64_t primary_key()const {
                    return sneaker.id;
                };
            };

            typedef multi_index<"users"_n, user> users;
            typedef multi_index<"sneakers"_n, sneaker> sneakers;
    };
}



