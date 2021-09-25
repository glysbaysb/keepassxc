/*
 *  Copyright (C) 2021 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "UnlockSSHKey.h"

#include "Utils.h"
#include "cli/TextStream.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Global.h"
#include "core/Group.h"
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/SSHAgent.h"

#include <QCommandLineParser>
#include <QLocale>

const QCommandLineOption UnlockSSHKey::AllOption =
    QCommandLineOption(QStringList() << "a"
                                     << "all",
                       QObject::tr("Unlock all the SSH keys in the database."));

UnlockSSHKey::UnlockSSHKey()
{
    name = QString("unlock-ssh-key");
    description =
        QObject::tr("Unlock one of multiple ssh keys from the database and add them to the running SSH agent.");
    options.append(UnlockSSHKey::AllOption);
    optionalArguments.append(
        {QString("entry"), QObject::tr("Name of the entry with an SSH key to unlock."), QString("")});
}

int UnlockSSHKey::executeWithDatabase(QSharedPointer<Database> database, QSharedPointer<QCommandLineParser> parser)
{
    auto& out = Utils::STDOUT;
    auto& err = Utils::STDERR;

    const QStringList args = parser->positionalArguments();
    const QString& entryPath = args.at(1);
    bool unlockAll = parser->isSet(UnlockSSHKey::AllOption);

    if (unlockAll) {
        sshAgent()->databaseUnlocked(database);
        out << QObject::tr("Successfully added all the SSH keys to the SSH agent.") << endl;
        return EXIT_SUCCESS;
    }

    Entry* entry = database->rootGroup()->findEntryByPath(entryPath);
    if (!entry) {
        err << QObject::tr("Could not find entry with path %1.").arg(entryPath) << endl;
        return EXIT_FAILURE;
    }

    OpenSSHKey key;
    KeeAgentSettings settings;

    if (settings.toOpenSSHKey(entry, key, true)) {
        if (!settings.fromEntry(entry)) {
            return EXIT_FAILURE;
        }
        // @hifi: Should I check for the KeeAgent settings from the CLI?
        // if (!KeeAgentSettings::inEntryAttachments(currentEntry->attachments())) {
        // return EXIT_FAILURE;
        // }

        SSHAgent::instance()->addIdentity(key, settings, database->uuid());
        out << QObject::tr("Successfully added SSH key from entry %1 to the SSH agent.").arg(entryPath) << endl;
        return EXIT_SUCCESS;
    } else {
        err << QObject::tr("Error while adding  SSH key from entry %1 to the SSH agent: %2.")
                   .arg(entryPath, key.errorString())
            << endl;
        return EXIT_FAILURE;
    }
}
