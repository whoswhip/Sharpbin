## [3.0.3](https://github.com/whoswhip/Sharpbin/compare/v3.0.2...v3.0.3) (2026-02-10)


### Bug Fixes

* correct spelling of 'Verification' in PasteSettings and PasteController ([697ec38](https://github.com/whoswhip/Sharpbin/commit/697ec384f8a0d3d86eb7e523595ddda3cda256b4))
* do not generate open api documents on build ([e901849](https://github.com/whoswhip/Sharpbin/commit/e90184992a1dd585bfb3728dc866193ab870fb86))
* ensure length > 0 and that arrays have value before validating ([f95b347](https://github.com/whoswhip/Sharpbin/commit/f95b347191854e8057c8086e52165a83e2fa8a7d))
* initialize multiselect state in modal component ([908441d](https://github.com/whoswhip/Sharpbin/commit/908441de4b7e857d8cbcc520da86cf1abaab0fa2))
* prevent internal server endpoint leakage in openapi ([4917180](https://github.com/whoswhip/Sharpbin/commit/4917180624d1ec2f7af784c50c5cd2810beba1b3))
* resolve lint issues ([b56a848](https://github.com/whoswhip/Sharpbin/commit/b56a848d21da5d8bb57c22bdc03bd84449813338))
* simplify height adjustment logic for text area and markdown container ([f37e647](https://github.com/whoswhip/Sharpbin/commit/f37e647a1c0264a3b6229c270e75b8176ec93628))
* update display name validation to allow spaces and improve error message ([755b356](https://github.com/whoswhip/Sharpbin/commit/755b356d616a339273c7e45207304e901617c367))
* update stats tooltip to display correct pluralization for paste counts ([54ca2ee](https://github.com/whoswhip/Sharpbin/commit/54ca2ee6417e0a6cfcc14ccb0be6e79d9dc4cacd))


### Features

* add statistics link to footer component ([cbbed2d](https://github.com/whoswhip/Sharpbin/commit/cbbed2d341670ba7b034af161ccdb3ddb3101dc0))
* add statistics page ([22317a2](https://github.com/whoswhip/Sharpbin/commit/22317a2fae8f8a8ed45f313a46bb2489b8042f92))
* allow spaces in display names ([abcf79c](https://github.com/whoswhip/Sharpbin/commit/abcf79c6458b97d1f75b6c31020fdc7ab957d4f2))
* **backend:** allow spaces in display name during registration ([71363fa](https://github.com/whoswhip/Sharpbin/commit/71363fa1a467c660297301d4f35513bdfe39ccd5))
* cache for 6 hours instead of 24 hours ([d04e296](https://github.com/whoswhip/Sharpbin/commit/d04e2962b51796393f77b66fd37f6efad924b413))
* enhance API stats endpoint to include daily paste counts for the past week ([23e7973](https://github.com/whoswhip/Sharpbin/commit/23e7973e972f197954568fb292f1c8f6e5272c50))
* implement web worker for syntax highlighting using highlight.js ([1cd6d16](https://github.com/whoswhip/Sharpbin/commit/1cd6d16d8538bf3b990f523703eb9abc19da5f36))
* proxy openapi url ([698db0a](https://github.com/whoswhip/Sharpbin/commit/698db0a85e000e8b1ab76d82827b8f404ffd0f67))
* true total paste size; always map the openapi route ([6b32994](https://github.com/whoswhip/Sharpbin/commit/6b32994d16b201a5a99037fcb23af30bd35876bc))
* update tooltip function to accept parameters for styling ([c9591a4](https://github.com/whoswhip/Sharpbin/commit/c9591a43c78b7c8a09b3e7afa0e8b401b70efae0))



## [3.0.2](https://github.com/whoswhip/Sharpbin/compare/v3.0.1...v3.0.2) (2026-01-31)


### Bug Fixes

* add IValidateableObject interface to required DTO's ensuring model validation ([270360a](https://github.com/whoswhip/Sharpbin/commit/270360a32f9b9217a1be1057058a61c57f578e95))
* adjust input margin for title field in paste creation ([d2486b9](https://github.com/whoswhip/Sharpbin/commit/d2486b9f6e1b87e2d4e13fcc2550292ad77170c3))
* enable AllowMissingPrunePackageData in project configuration ([c52ad8b](https://github.com/whoswhip/Sharpbin/commit/c52ad8ba9b12e62324fc6bac445a3e1c5b275e95))
* improve error handling and update user display name modal ([a6ffa98](https://github.com/whoswhip/Sharpbin/commit/a6ffa982a4225ef4512b925af39ed4836be40fbb))
* update version to 3.0.1 in package-lock.json ([15f0be5](https://github.com/whoswhip/Sharpbin/commit/15f0be5a2f902429906c1acdfe7923b25c16be12))


### Features

* add conventional-changelog and conventional-changelog-angular dependencies ([e4cf98a](https://github.com/whoswhip/Sharpbin/commit/e4cf98af096b4909e97898eaa452447a09307d31))
* add inputMaxLength property to Modal component for better input control ([005cb5d](https://github.com/whoswhip/Sharpbin/commit/005cb5de23e244a4b07ea1173b7805f7cd2b2561))
* add output caching and stats endpoint to track pastes and users ([ca210c5](https://github.com/whoswhip/Sharpbin/commit/ca210c5ea3e97d7a4e93f51794d1da7a6da40ebf))
* createdAt paste property ([9d0cc54](https://github.com/whoswhip/Sharpbin/commit/9d0cc54db46a24d16f752b5db66baf1565891d26))
* enhance PasteService with caching and cache invalidation methods ([5375e1c](https://github.com/whoswhip/Sharpbin/commit/5375e1caa64ce51bd0cd3613f8df68d6ea2d7aa4))
* include createdAt in user responses ([854e50f](https://github.com/whoswhip/Sharpbin/commit/854e50fe78265a58af6004c3db12ca551c4372f9))
* include paste createdAt in responses ([8aa1543](https://github.com/whoswhip/Sharpbin/commit/8aa1543296817745f66a724e349897d8496bb193))
* user createdAt property ([500f457](https://github.com/whoswhip/Sharpbin/commit/500f457f976bc4742e8e3395f01eef84a0c16558))



## [3.0.1](https://github.com/whoswhip/Sharpbin/compare/v3.0.0...v3.0.1) (2026-01-27)


### Bug Fixes

* adjust dropdown max height dynamically and improve search input positioning ([2d01e72](https://github.com/whoswhip/Sharpbin/commit/2d01e726a97b99a35017df9f477fa1304213bc9e))
* adjust height properties for paste creation info ([01efa39](https://github.com/whoswhip/Sharpbin/commit/01efa399cf7d7aa1d38af1bc29017a8873f97dca))
* adjust tooltip formatting for decrypted size display ([a7481b5](https://github.com/whoswhip/Sharpbin/commit/a7481b5852532d42697e723f8f49cfa126ce8212))
* allow flexible display on cf turnstile ([3681f58](https://github.com/whoswhip/Sharpbin/commit/3681f586dc0a01fcfd197db3961386d4ac7fe371))
* disable pointer events on menu icons ([590f0c3](https://github.com/whoswhip/Sharpbin/commit/590f0c3da9c4bd6f9db43a5866dddfb9a2859326))
* enhance password validation and add show/hide functionality ([ec62e3b](https://github.com/whoswhip/Sharpbin/commit/ec62e3be7556f083ef8380dd4eece4f5e5b4f148))
* enhance Paste component layout and user information display ([4db9867](https://github.com/whoswhip/Sharpbin/commit/4db986715cfd36d300677b7e527ff8e2de827791))
* include author data in recent paste data ([c9aa0d9](https://github.com/whoswhip/Sharpbin/commit/c9aa0d9a16f9135be7be4b100c6c0966f3285e6a))
* render all turnstiles as flexible and interaction-only ([75010d3](https://github.com/whoswhip/Sharpbin/commit/75010d303424a45d9435571b45e4d0d29ade23a9))
* resize markdown preview as well ([51449ab](https://github.com/whoswhip/Sharpbin/commit/51449abe6e894d289374ec7ffcef21ff3d1e71c9))
* resolve lint issue svelte/no-at-html-tags ([71fb5b1](https://github.com/whoswhip/Sharpbin/commit/71fb5b16160aa986ca577c25373dcc382ff96ba3))
* update Open Graph description to use syntax name from consts ([a06021f](https://github.com/whoswhip/Sharpbin/commit/a06021f0cd67162446d9393a854ddc4f7f3a74b0))
* update resize function call to use `previewMode` ensuring resize when switched to code ([16f5bff](https://github.com/whoswhip/Sharpbin/commit/16f5bff317a6620e3a7e5a0fd99ac6b56599dd8e))
* update Turnstile configuration and improve layout for verification ([9c49c21](https://github.com/whoswhip/Sharpbin/commit/9c49c21e62118d277670677e51a685150194a2b6))
* update visibility icons in Paste component ([6c8cdcc](https://github.com/whoswhip/Sharpbin/commit/6c8cdccbbfd3becdd5fae4674909c788f00edab7))


### Features

* add CSV rendering functionality with PapaParse ([bfad18b](https://github.com/whoswhip/Sharpbin/commit/bfad18bb0551ddc2eb03f934ecedd2b7b89ddbf2))
* add CSV to syntax lists ([147e43c](https://github.com/whoswhip/Sharpbin/commit/147e43cd8ab32da538e6ff76a68cdb7441e469e2))
* add papaparse and its type definitions ([95316f5](https://github.com/whoswhip/Sharpbin/commit/95316f5a846c03a5e2b014717c26bea9005f933d))
* add tailwind-scrollbar npm package ([43f9a25](https://github.com/whoswhip/Sharpbin/commit/43f9a25915ac32076636ab86781aa7efb5240b41))
* close hamburger menu when clicked outside ([1937307](https://github.com/whoswhip/Sharpbin/commit/1937307ae728f0d77c9ee572adf1ba688648e0aa))
* enhance CSV rendering with header support and improved styling ([c940fc5](https://github.com/whoswhip/Sharpbin/commit/c940fc5207a80563a620b37c9aeebce395c659e9))
* include decrypted size in paste size tooltip ([7082fc4](https://github.com/whoswhip/Sharpbin/commit/7082fc45346824f14d6f8fe85743f73eca6a35c1))
* style dropdown scrollbar ([091c6d8](https://github.com/whoswhip/Sharpbin/commit/091c6d895e638fc13b68207e3ae765664dfc80b6))



# [3.0.0](https://github.com/whoswhip/Sharpbin/compare/050f0bc935937b8b80500a59bc6ac5513fd7af93...v3.0.0) (2026-01-24)


### Bug Fixes

* add ASPNETCORE_URLS environment variable for backend service in docker-compose.yml ([c4f606e](https://github.com/whoswhip/Sharpbin/commit/c4f606ecf265678495b616a11c0fab1aa4ca9331))
* add cursor pointer to the submit button for better UX ([f5de211](https://github.com/whoswhip/Sharpbin/commit/f5de211611c8142c0825286c0f514b1edc161d51))
* add validation for display name length in user creation and update requests ([9bb620a](https://github.com/whoswhip/Sharpbin/commit/9bb620a4a31473385af6ffd32d2b7d7c5affd415))
* adjust password hint display logic in registration form ([361cf76](https://github.com/whoswhip/Sharpbin/commit/361cf76f46598c1d797c745e44f2de5d960682bc))
* center-align text in login and registration links in navbar ([4dafde7](https://github.com/whoswhip/Sharpbin/commit/4dafde739aaf04d4a7b0e08ee15415518bcf2e7b))
* change to non-reactive statements ([55bee20](https://github.com/whoswhip/Sharpbin/commit/55bee20e5de3d4c155f2eaa0f7999110a86aa535))
* correct conditional logic for user role checks in component rendering ([7298982](https://github.com/whoswhip/Sharpbin/commit/729898296b4e09fa8cada5feb524f1d3774a2d7c))
* correct environment variable key for Turnstile Site Key in docker-compose ([2773813](https://github.com/whoswhip/Sharpbin/commit/2773813c263d59a20ceabd02ebabd763a3832ebc))
* correct property name for TOTP enabled flag in parseTotpEnabled function ([9e56c4e](https://github.com/whoswhip/Sharpbin/commit/9e56c4eee1d97227b821d643640d2d1db593aba7))
* correct syntax selection logic for file drag and drop handling ([62b5dce](https://github.com/whoswhip/Sharpbin/commit/62b5dcef00e6230ec8674d3de65617216e760e51))
* display 2FA status only for the account owner ([4de6a6a](https://github.com/whoswhip/Sharpbin/commit/4de6a6a1186e97a7063d5e55008f9acc5043b912))
* dont disabled login button when registrations are disabled ([bbfa9ff](https://github.com/whoswhip/Sharpbin/commit/bbfa9ffc560a87bcc8441fddc6d78496819a9144))
* enhance paste size validation logic ([f467a2a](https://github.com/whoswhip/Sharpbin/commit/f467a2a89966e6025d7ac0a60eb89c99956e4d28))
* enhance textarea styling and display content metrics ([fabef95](https://github.com/whoswhip/Sharpbin/commit/fabef95159e469abcf6316362f18de25aab0a0c6))
* enhance tooltip functionality and update last login display ([d3c2efd](https://github.com/whoswhip/Sharpbin/commit/d3c2efd2108026b5e49f1a199c6f2afdeb0a06a0))
* ensure JSDOM is only loaded in server-side environments ([7789ab6](https://github.com/whoswhip/Sharpbin/commit/7789ab6cb2822ca338186573c010047a3c5b0f48))
* improve error handling and display for login failures ([ce66fe1](https://github.com/whoswhip/Sharpbin/commit/ce66fe13e8718b8abbf67adca9fa1775c932401f))
* improve error handling and response messages in EditPaste method ([284c5e9](https://github.com/whoswhip/Sharpbin/commit/284c5e927e1ef796026ca1b1a078adadc1986721))
* improve error handling for registration response ([d514e45](https://github.com/whoswhip/Sharpbin/commit/d514e456bf364b1dbdbd7e67938ca609c2362468))
* improve error handling in paste fetching and add error page ([5e4afaf](https://github.com/whoswhip/Sharpbin/commit/5e4afafac0e57a24316761c555892fee5dc8394a))
* improve error logging for view count increment failure ([8b84a2d](https://github.com/whoswhip/Sharpbin/commit/8b84a2d8a3dbcfa0909a9ba7ac79531244c268f2))
* improve formatBytes function and display byte size in textarea ([2a9a4b9](https://github.com/whoswhip/Sharpbin/commit/2a9a4b9eefaef513df5437a9d548e1941583fc1e))
* include url queries in resolve ([7857c32](https://github.com/whoswhip/Sharpbin/commit/7857c327eac1a2371552bedc1571650bffb29c0d))
* increase max height ([7650fd7](https://github.com/whoswhip/Sharpbin/commit/7650fd786dbcffb9cba6aba9c073d9ec5e19c737))
* inline is expired calculation ([2b60ee8](https://github.com/whoswhip/Sharpbin/commit/2b60ee86369731ebc98deaf007c725a544382b2a))
* lint issues resolved ([21b6f95](https://github.com/whoswhip/Sharpbin/commit/21b6f95edc1ff34a3ee66f32083b4f99d9bbf2ac))
* load turnstile script in layout and explicitly render ([2c24af5](https://github.com/whoswhip/Sharpbin/commit/2c24af5ac98dd4959e353571d3186fb98b459bf4))
* null user/paste fk in reports on delete ([f8a1490](https://github.com/whoswhip/Sharpbin/commit/f8a149058295ebc56fc43cecf03b76792fc62529))
* prevent moderators from modifiying higher roles(admin) ([3711885](https://github.com/whoswhip/Sharpbin/commit/3711885a38e18ddf6e478e17c671c4c7774c0d3e))
* properly set limiter ([6f99036](https://github.com/whoswhip/Sharpbin/commit/6f990364a59b0a9801a6dbd715c70c2f29e63e9c))
* refresh token ([19f439a](https://github.com/whoswhip/Sharpbin/commit/19f439a4052d16a3bddba36dc15822906ca92e11))
* remove dependency condition for backend service health check in docker-compose.yml ([095df2f](https://github.com/whoswhip/Sharpbin/commit/095df2f3f3aff1eccf4f023ca1a77bc11d66bbea))
* remove quotes from DATA_PROTECTION_KEY_PATH in docker-compose ([f96396b](https://github.com/whoswhip/Sharpbin/commit/f96396b586f5f0b5da66227c08767be348f5cbab))
* remove quotes from default connection string in docker-compose ([d5565f9](https://github.com/whoswhip/Sharpbin/commit/d5565f9a68bf38035d994002812c3411427f563e))
* remove unused nuget package ([4bd6a18](https://github.com/whoswhip/Sharpbin/commit/4bd6a18e31970f4568f0d405454c30b56e06c895))
* reset Turnstile on login and registration error handling ([5a630d2](https://github.com/whoswhip/Sharpbin/commit/5a630d2a715acc851add8f82b19dba111d98c2bd))
* reset turnstile on login error handling ([1da88db](https://github.com/whoswhip/Sharpbin/commit/1da88dba4ed500baf6dc57b6eeb02b115c0fd000))
* resolve lint issues ([1f4fda1](https://github.com/whoswhip/Sharpbin/commit/1f4fda1a16f92cebae716642482d959ad300c5a7))
* ssr request to user; navbar positioning ([bffc4e2](https://github.com/whoswhip/Sharpbin/commit/bffc4e2bf41fe1a3dd93f3042be0e796b6f986d2))
* **style:** update Navbar styling for improved layout and consistency ([6c3caaf](https://github.com/whoswhip/Sharpbin/commit/6c3caaf2ecaa6dc9e616d7f5a7f65ee1a15c091c))
* **styling:** add table styling for markdown elements ([825d384](https://github.com/whoswhip/Sharpbin/commit/825d384db4c906f373ea92ae3e4b46efd741e862))
* **styling:** adjust margin and padding for first child in markdown elements ([8f5499a](https://github.com/whoswhip/Sharpbin/commit/8f5499ae05f69c131447fef6188680d448ed895e))
* **styling:** enforce max width on recent pastes titles ([8accfa2](https://github.com/whoswhip/Sharpbin/commit/8accfa2dc525f528337e2cbd79ab6a6a2c2b748f))
* token refreshing using wrong object path ([e45785e](https://github.com/whoswhip/Sharpbin/commit/e45785e1b8bb64a0834cf420db4866307146132d))
* update API fetch calls to use dynamic apiUrl ([6072f7f](https://github.com/whoswhip/Sharpbin/commit/6072f7f674bc3def903815de35536ed933cff7fd))
* update API routes for fetching raw paste content and deleting pastes ([48543c7](https://github.com/whoswhip/Sharpbin/commit/48543c7ff03b1ff4b3efa96de56097fb9ada2f02))
* update database connection string configuration in Program.cs and docker-compose.yml ([011b523](https://github.com/whoswhip/Sharpbin/commit/011b523fd321e0834c73790b2553adee37a022f6))
* update docker-compose to reflect correct backend directory structure ([113ad49](https://github.com/whoswhip/Sharpbin/commit/113ad499d9806a7a237f6afdb9a6bf02ebc238aa))
* update environment variables in docker-compose for backend and frontend services ([5e8d7be](https://github.com/whoswhip/Sharpbin/commit/5e8d7be86423247e63a350d440bc52cf3428d312))
* update Navbar and layout server to improve structure and data handling ([a912d04](https://github.com/whoswhip/Sharpbin/commit/a912d0463b1e8517f055f596c2cb033b88db6b9b))
* update paste view count display in metadata ([f9b63ed](https://github.com/whoswhip/Sharpbin/commit/f9b63edf776e2715b09de2d408aab4ba85ccd50f))
* update profile link to direct to user page instead of dashboard ([ff52498](https://github.com/whoswhip/Sharpbin/commit/ff52498cf99a74936d47d73369c7fdd7b771f0df))
* update SQLite connection string retrieval in Program.cs ([6178888](https://github.com/whoswhip/Sharpbin/commit/6178888246871f38ab8373bacbb2a61fba6d4046))
* update TOTP API request payload to use 'code' instead of 'totpcode' ([6bcc62a](https://github.com/whoswhip/Sharpbin/commit/6bcc62a7e7b77c1129c16d9a8c979e003b6481e5))
* update version number to 3.0.0 and remove beta check from footer ([8252d58](https://github.com/whoswhip/Sharpbin/commit/8252d58f47d503a0c40f95bde9ee277341e801b9))
* use $app/state ([b44f0bc](https://github.com/whoswhip/Sharpbin/commit/b44f0bce0ab5f7fcedf9c206362a31947215eef9))
* use margin-bottom instead of margin-top for elements ([bd7d115](https://github.com/whoswhip/Sharpbin/commit/bd7d1154eaf57e310a82cb43c09baf15c499a489))


### Features

* /raw/{id} endpoint ([ca87b1a](https://github.com/whoswhip/Sharpbin/commit/ca87b1a5f220a6f3b8857cf00602abf867c9a7d9))
* account deletion; auto incremental uids; display name renaming UI + account deletion UI; enhanced username validation ([fe54ff1](https://github.com/whoswhip/Sharpbin/commit/fe54ff15ce7122373643eece9981eb05a1d7c7d0))
* add application version definition to Vite config ([eca6867](https://github.com/whoswhip/Sharpbin/commit/eca6867fcab5c1ba4d1d327c76f18fd21290abd6))
* add delete functionality for pastes with authorization check ([3015f97](https://github.com/whoswhip/Sharpbin/commit/3015f97ff977fbfd9b23a11aad016ac7408be752))
* add Dockerfile and docker-compose for backend and frontend services ([31142e0](https://github.com/whoswhip/Sharpbin/commit/31142e0cf96d2ff868fadf1ecac192a07ebc5c2d))
* add editedAt field to Paste interface and enhance paste editing functionality ([86b74a1](https://github.com/whoswhip/Sharpbin/commit/86b74a140a546651d301079b71531468d0b1d52d))
* add Footer component to layout for improved user navigation ([e093550](https://github.com/whoswhip/Sharpbin/commit/e0935505ea01c286cb802337461b1ebbb4eb6f2d))
* add health check endpoint returning status ok ([dfdce51](https://github.com/whoswhip/Sharpbin/commit/dfdce51c6e648b601880a16644d7790b41550129))
* add health checks for backend and frontend services in docker-compose.yml ([08c4be4](https://github.com/whoswhip/Sharpbin/commit/08c4be4f7eb8e985114d1f87a8bd69a7bad0a9ee))
* add health checks for backend and frontend services in docker-compose.yml ([57dad56](https://github.com/whoswhip/Sharpbin/commit/57dad564a6df35ea488fab40fa9798511036d4ac))
* add health checks for database connectivity ([cab1b17](https://github.com/whoswhip/Sharpbin/commit/cab1b170c1218c47c5c4f366425731c3fdb5d67a))
* add isBinaryData utility function and integrate it into paste handling; add drag and drop functionality when creating a paste ([bf0eac9](https://github.com/whoswhip/Sharpbin/commit/bf0eac9ed8aa00cf4d82236cf8257f87bc6b8588))
* add markdown parsing and rendering support ([406381f](https://github.com/whoswhip/Sharpbin/commit/406381fbfe724249b41477f64ef42116882a671d))
* add Pagination interface and integrate it into User type ([a9e1e82](https://github.com/whoswhip/Sharpbin/commit/a9e1e823591c01be4dc960bf5427131480dfa413))
* add pagination to user retrieval endpoints; enhance BuildUserResponse to include pagination details ([93df14e](https://github.com/whoswhip/Sharpbin/commit/93df14e59ce876c877d34d28a9f0a0cf3d53eb28))
* add PasteCleanUpService as a hosted service ([f578b58](https://github.com/whoswhip/Sharpbin/commit/f578b58780930d253837d4e1c795f46c6b27b9df))
* add PasteSettings environment variables for internal API key and HMAC secret ([a6fa65c](https://github.com/whoswhip/Sharpbin/commit/a6fa65c3bd67fbb1133737d738626c345304f503))
* add recent pastes page with data fetching and display logic ([8a6ab29](https://github.com/whoswhip/Sharpbin/commit/8a6ab29f52ddd6e05c211569323d0d4d48b4938b))
* add registration status check and disable form elements when registration is disabled ([b1d2d3f](https://github.com/whoswhip/Sharpbin/commit/b1d2d3f5bba5e7f0bab38448fc25baa8a4551317))
* add variant support for dropdown component styling ([1950dc4](https://github.com/whoswhip/Sharpbin/commit/1950dc47ae8c5ca721851999afb2ce32b7c5c4cb))
* admins can change user's roles ([99feb27](https://github.com/whoswhip/Sharpbin/commit/99feb2795a17b43724985cbf1722088fde0ac281))
* auth, compression, jwt, paste wip, roles, ratelimiting ([6ec1a7f](https://github.com/whoswhip/Sharpbin/commit/6ec1a7fa7b3254e6ab09aaed8943534b79dac9cd))
* auto detect syntax from file extension on drag and drop; syntax from extension function ([9e05600](https://github.com/whoswhip/Sharpbin/commit/9e056009e3858d9a56bd71638cd32db3ce122a60))
* bypass user confirmation when loading external assets in markdown for trusted domains ([35d891b](https://github.com/whoswhip/Sharpbin/commit/35d891bed7bd7fb2415a14e74f45eb5b7d4e3453))
* create Paste component for displaying paste details ([753d28f](https://github.com/whoswhip/Sharpbin/commit/753d28f720c9f7f6a3b7d787ca19a8149d592ee7))
* declare application version constant in app.d.ts ([72206e9](https://github.com/whoswhip/Sharpbin/commit/72206e9ba214b602cafd2836d880ac06debb69de))
* enable registration toggle and update Navbar to reflect registration status ([159fcc2](https://github.com/whoswhip/Sharpbin/commit/159fcc2a890480cfad0cc19dd153c84aa1af88d0))
* enhance AuthService to support admin role assignment for the first user ([c934c85](https://github.com/whoswhip/Sharpbin/commit/c934c85b130d2c0086146110f3211f612387b8d3))
* enhance code highlighting for plaintext in syntax highlighter ([5cb30a9](https://github.com/whoswhip/Sharpbin/commit/5cb30a90a760874d54cc18e0adc63cfe6812d1c7))
* enhance decryption process with status updates and improved user feedback ([7b3af77](https://github.com/whoswhip/Sharpbin/commit/7b3af774494c31f8fcd829d20f9bb5f46242320a))
* enhance paste creation with dynamic textarea resizing and improved password handling; generate random password button in paste creation; show password in paste creation; ([5410a89](https://github.com/whoswhip/Sharpbin/commit/5410a8973a81dc6a854f1c685e3a3546de985486))
* enhance tooltip functionality and improve date formatting ([8ab66f5](https://github.com/whoswhip/Sharpbin/commit/8ab66f5f159c1c34d29c456fef9a4c626548c6aa))
* enhance tooltip functionality; prevent empty tooltips for paste titles ([7eb0204](https://github.com/whoswhip/Sharpbin/commit/7eb0204e6751df148b6520c6ccd665289e31341b))
* enhance user experience with tooltips; implement return URL handling on login and registration; add user roles; improve paste visibility checks ([5fca207](https://github.com/whoswhip/Sharpbin/commit/5fca207ad61acf0dca4c9fd13ab5a598d89ba890))
* implement decryptAes function; moved to encryption.ts ([f61f31d](https://github.com/whoswhip/Sharpbin/commit/f61f31de0e9a3c97a347d38783cddb4c0d7f83fe))
* implement mobile support for navbar ([63f55d2](https://github.com/whoswhip/Sharpbin/commit/63f55d2bdac475bd7d981d87475fa4e8cddb6b72))
* implement modal component for password input and confirmation actions ([b6e020f](https://github.com/whoswhip/Sharpbin/commit/b6e020fa6987b5ecad5ca78d24ce87e41799c177))
* implement pagination for user pastes; enhance fetchPage function and update display logic ([49b9673](https://github.com/whoswhip/Sharpbin/commit/49b9673d48d50a5ca2adea9b4c2055ae2c88f001))
* implement paste decryption ([3a54951](https://github.com/whoswhip/Sharpbin/commit/3a549511f93d7001d246c318545e6edb307e2f99))
* implement rate limiting policy for site info endpoints in Auth and Paste controllers ([3895bd9](https://github.com/whoswhip/Sharpbin/commit/3895bd968136071cc09bba686107f693f7e47dc3))
* implement registration page with Turnstile verification and loading state ([24b25c2](https://github.com/whoswhip/Sharpbin/commit/24b25c2291eea16fab16c250b5856b91f7385b74))
* implement server-side user data fetching; enhance user controller for detailed responses; update token handling to use cookies ([4151c62](https://github.com/whoswhip/Sharpbin/commit/4151c62b8cd10cdbf6a757f6e82935e8d5426a5a))
* implement Turnstile verification for enhanced security during login and registration ([848b859](https://github.com/whoswhip/Sharpbin/commit/848b8598e5fb407f284027875c1f09c396b4aa6f))
* implement user update functionality by UUID and add validation to UpdateUserRequest ([f40d4ab](https://github.com/whoswhip/Sharpbin/commit/f40d4ab68c3aabf95b8775601b1534bda9665b4b))
* improve file download naming by using syntax extension conditionally ([fed0663](https://github.com/whoswhip/Sharpbin/commit/fed06630b7383eb185b2afbdfd30d2776416bcc5))
* improve paste creation validation; add content size check and remove unnecessary logging ([dd6ce5c](https://github.com/whoswhip/Sharpbin/commit/dd6ce5c39506e9e22aeefa4db34ac8caa48a5cdd))
* improve recent page; improve SEO for pages ([3a5738b](https://github.com/whoswhip/Sharpbin/commit/3a5738b53173ddae500098ffcbf1769dada11584))
* initial commit ([050f0bc](https://github.com/whoswhip/Sharpbin/commit/050f0bc935937b8b80500a59bc6ac5513fd7af93))
* integrate hash-wasm for enhanced AES encryption and decryption ([7e1fb3a](https://github.com/whoswhip/Sharpbin/commit/7e1fb3add4f438a206638ea0c90b0a27fd108c53))
* login & registration; enhanced paste view; custom dropdown + search; navbar; global user access via store; auto token refresh; paste creation as user; /api/user/me, returns info on yourself including pastes; ([db1d870](https://github.com/whoswhip/Sharpbin/commit/db1d8704a1d0f183812fbd41ad077274c6626801))
* paste cleanup service; sveltekit frontend; paste editing; paste metadata modifying ([adad139](https://github.com/whoswhip/Sharpbin/commit/adad139081fb4d9b2ed644e8fe4cdd89ac2ef38d))
* paste compression & verification enforcement settings; enforce 2fa on admins setting; increase paste validation; anonymous uploads ([9f55aa1](https://github.com/whoswhip/Sharpbin/commit/9f55aa1b2273ee0298892dba380c71630c743289))
* paste creation, utilities, revert to gzip, grammar fixes etc ([93daa2e](https://github.com/whoswhip/Sharpbin/commit/93daa2e1a2b75cc2e93cbc7149b837e79eb9ece4))
* paste creation; paste viewing; more langs supported; jwt settings class; paste settings class; data validation on paste metadata modification ([b9b14a3](https://github.com/whoswhip/Sharpbin/commit/b9b14a3d5a553fd1e7e7294c8ba29cd8cb8218dd))
* paste views; configuration validation; hmacsha256 method; enhance paste clean up serivce; paste view clean up service; ([3048af3](https://github.com/whoswhip/Sharpbin/commit/3048af3a6dece0338e278bf6d6b2358c0f4952fc))
* preview markdown in paste creation; prevent external option in parseMarkdown ([3f27a3a](https://github.com/whoswhip/Sharpbin/commit/3f27a3a3e726e941ad6e996db53f9366506a7012))
* refactor drag and drop file handling to update syntax selection conditionally ([ca9fa81](https://github.com/whoswhip/Sharpbin/commit/ca9fa81771af49b20628c148a1ac61ad6a168bf9))
* refactor refresh token handling; update schema and logic for improved security and functionality ([ae91108](https://github.com/whoswhip/Sharpbin/commit/ae91108484ff73a6cdee16e0454acc330a221a33))
* reporting apis; better rate limiting ([14bbd9c](https://github.com/whoswhip/Sharpbin/commit/14bbd9c762f641ac738714822d19845d86bb6582))
* reports; improved+simplifed modals; extractError funcction; ([67447d5](https://github.com/whoswhip/Sharpbin/commit/67447d51aec59af200524e7f33bcee5678adc2bc))
* seo optimizations + opengraph embeds ([3bbd646](https://github.com/whoswhip/Sharpbin/commit/3bbd64631a46d510e720db3a3d5cf7ad4298702d))
* totp 2fa; httpcontext extension for jwtuser; asp.net data protection; prevent banned users from certain actions; account deletion requires 2fa if enabled; making users admins requires 2fa if enabled; httpcontext extension to get ip; enhance user store ([20ceb91](https://github.com/whoswhip/Sharpbin/commit/20ceb91db8405172d5beb9df646d3d912cea40a5))
* update API routes for paste options and recent pastes ([1f2761f](https://github.com/whoswhip/Sharpbin/commit/1f2761f463e160a0d4d865a4d6a5763fc408712b))
* update button styles for active state in paste creation ([6981836](https://github.com/whoswhip/Sharpbin/commit/698183690c1b48b6e6ebf83f62025242d746c607))
* update favicon and improve tooltip for paste size display ([1ed2178](https://github.com/whoswhip/Sharpbin/commit/1ed21789e656dfdc7a65119f4c5ec010a1669593))
* update minimum height for main sections across multiple pages for consistent layout ([c565c57](https://github.com/whoswhip/Sharpbin/commit/c565c57e20cb0eb7d6e57e17182382e2ee931190))
* view raw button; paste header follows when scrolling; scroll to top button appears after scrolling far enough ([28a0ccb](https://github.com/whoswhip/Sharpbin/commit/28a0ccbfab4461fd6fe75d25b3f7cffce063041f))


### Reverts

* Revert "chore: format via csharpier" ([6bea6c4](https://github.com/whoswhip/Sharpbin/commit/6bea6c49bef1eea4dfd72d962b4e06e20b64594f))



