#!/bin/bash

# Chemins des fichiers source
source_service="/etc/blocklist/systemd/blocklist.service"
source_timer="/etc/blocklist/systemd/blocklist.timer"

# Chemins des liens symboliques dans /etc/systemd/system/
link_service="/etc/systemd/system/blocklist.service"
link_timer="/etc/systemd/system/blocklist.timer"

# Fonction pour créer un lien symbolique
create_symlink() {
    local source_file=$1
    local link_file=$2
    local response

    # Vérifier si le lien symbolique existe
    if [ -L "$link_file" ]; then
        # Demander à l'utilisateur s'il veut le remplacer
        read -p "Le lien symbolique $link_file existe déjà. Voulez-vous le remplacer ? (y/n) " response
        if [[ "$response" == "y" ]]; then
            # Supprimer le lien existant et en créer un nouveau
            rm "$link_file"
            ln -s "$source_file" "$link_file"
            echo "Le lien symbolique a été remplacé : $link_file"
        else
            echo "Le lien symbolique n'a pas été remplacé : $link_file"
        fi
    else
        # Créer le lien symbolique
        ln -s "$source_file" "$link_file"
        echo "Lien symbolique créé : $link_file"
    fi
}

# Créer ou remplacer les liens symboliques
create_symlink "$source_service" "$link_service"
create_symlink "$source_timer" "$link_timer"

