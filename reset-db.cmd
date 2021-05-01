@echo off
echo resetting users.db...
copy /Y copy-users.db users.db && (
    echo ok ) || (
    echo ERROR resetting users.db
)
