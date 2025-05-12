#Import des modules
Using Module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.logger.psm1"
Using Module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.MS365.psm1"
Using module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.varonis.decrypt.psm1"
Using module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.varonis.sql.psm1"
Using module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.varonis.sql.models.psm1"
Using module "\\dsp\D$\Tools\AP24301\Scripts\vendor\bnpp.mailer.psm1"
Using module "\\dsp\D$\Tools\AP24301\Scripts\vendor\BNPPModuleClass.psm1"
Import-Module "\\localhost\C$\Program Files\Varonis\Database Adapter\Varonis.SQL.Crypto.dll"
 
cls

<###########################################################################################################>

# ============================================================================
# Classe OwnerFinder : la logique pour retrouver le propriétaire d'un dossier partagé à partir des statistiques d'accès, des permissions et des référentiels internes.
# ============================================================================
class OwnerFinder  {
    [VaronisSQL]$SQLConnexion = [VaronisSQL]::new() # Connexion SQL à la base Varonis
    [RefogModel]$RefogModel = [RefogModel]::new()  # Modèle pour accéder aux infos utilisateurs
    [hashtable]$CachedUSER = @{}                   # Cache pour éviter les requêtes redondantes
    [hashtable]$CachedManager = @{}                # Cache pour savoir si un UID est manager

    # Récupère un utilisateur à partir de son UID, avec cache
    [RefogModel] retreiveUserFromUID([String]$uid) {
        # Vérifie si l'utilisateur est déjà dans le cache pour éviter une requête inutile
        if($this.CachedUSER.ContainsKey($uid) -eq $false) {
            # Recherche l'utilisateur dans la base RefogModel avec l'UID fourni
            $user = ($this.RefogModel.SelectWhere("hr_I_UID LIKE '$($uid)'")[0]
            # Si utilisateur trouvé -> ajoute au cache pour les futures recherches
            if($user -ne $null) {
                $this.CachedUSER.Add($user.hr_I_UID, $user)
            }
        } else {
            # Si utilisateur dans le cache -> récupère directement
            $user = $this.CachedUSER[$uid]
        }
        # Retourne utilisateur ou $null si non trouvé
        return $user
    }

    # ------------------------------------------------------------
    # Récupère les statistiques d'accès à un dossier sur une période donnée
    # ------------------------------------------------------------
    [System.Data.DataRowCollection]getDirectoryStatistics([string]$ServerName, [string]$SharePath, [int]$LookupDays) {
        
        $mostActive = $this.SQLConnexion.Select("EXEC BNPPStatistics..spGetMostActiveUserForDirectory @FilerName = '$ServerName', @SharePath = '$SharePath', @LookupDays=$LookupDays")
        
        if($mostActive -eq $null) {
            return $null
        }
        # uniformiser les noms de comptes 
        $mostActive | ForEach-Object {
            $sam = [String]$_.SamAccountName
            if($sam.Length -ne 6) {
                $sam=$sam.Replace('ES','')
                $sam=$sam.Replace('PT','')
                $sam=$sam.Replace('UK','')
                $sam=$sam.Replace('.','')
                $sam=$sam.Replace('OLD','')
                $sam=$sam.Replace('_','')
                $_.SamAccountName = $sam
            }
        }
        return $mostActive
    }

    # ------------------------------------------------------------
    # Récupère les permissions sur un dossier
    # ------------------------------------------------------------
    [System.Data.DataRowCollection]getDirectoryPermissions([string]$ServerName, [string]$SharePath, [int]$IgnoreOpenAccess, [int]$IgnoreDisabledAccount) {
        $mostActive = $this.SQLConnexion.Select("EXEC BNPPStatistics..spGetDirectoryPermissions @FilerName = '$ServerName', @SharePath = '$SharePath', @IgnoreOpenAccess=$IgnoreOpenAccess, @IgnoreDisabledAccount=$IgnoreDisabledAccount")
        $mostActive | ForEach-Object {
            $sam = [String]$_.SamAccountName
            if($sam.Length -ne 6) {
                $sam=$sam.Replace('ES','')
                $sam=$sam.Replace('PT','')
                $sam=$sam.Replace('UK','')
                $sam=$sam.Replace('.','')
                $sam=$sam.Replace('OLD','')
                $sam=$sam.Replace('FRA01','')
                $sam=$sam.Replace('GAIA1','')
                $sam=$sam.Replace('_','')
                $_.SamAccountName = $sam
            }
        }
        return $mostActive
    }

    # ------------------------------------------------------------
    # Cette fonction crée une table de hachage qui associe chaque utilisateur à son nombre d'accès.
    # -> retrouver rapidement combien de fois chaque utilisateur a accédé au dossier.
    # ------------------------------------------------------------
    [Hashtable]formatStatsTable($mostActiveUsers) {
        $statsTable = @{}
        $mostActiveUsers | ForEach-Object {
            if($statsTable.ContainsKey($_['SamAccountName']) -eq $false) {
                $statsTable.Add($_['SamAccountName'], $_['EventsCount'])
            }
        }
        return $statsTable
    }

    # ------------------------------------------------------------
    # Cette fonction crée une table de hachage qui associe chaque utilisateur à 1 si il a accédé au dossier.
    # ------------------------------------------------------------
    [Hashtable]formatPermissionsTable($mostActiveUsers) {
        $statsTable = @{}
        $mostActiveUsers | ForEach-Object {
            if($statsTable.ContainsKey($_['SamAccountName']) -eq $false) {
                $statsTable.Add($_['SamAccountName'], 1)
            }
        }
        return $statsTable
    }

    # ------------------------------------------------------------
    # Calcule le nombre total d'événements dans sur un share
    # ------------------------------------------------------------
    [int]getTotalNumberOfEvents([hashtable]$stats) {
        $total = 0

        Foreach($StatLine in $stats.GetEnumerator()) {
               $total+=$StatLine.Value
        }
        return $total
    }

    # ------------------------------------------------------------
    # Calcule l'utilisation d'un PC par le CISO (sécurité)
    # ------------------------------------------------------------
    [int]getPCUsageCISO([string]$uid, $stats) {
        $total = 0 

        $user = $this.retreiveUserFromUID($uid)  # Récupère l'objet CISO via UID

        Foreach($StatLine in $stats.GetEnumerator()) {  # Parcourt la table de stats
            if($StatLine.Name -ne 'Undefined') {  # Ignore les utilisateur undefined
                $actualUser = $this.retreiveUserFromUID($StatLine.Name)  # Récupère l'objet correspondant à l'entrée
                if($user.rssiUid -eq $actualUser.rssiUid) {  # Vérifie si c'est le CISO
                    $total+=$StatLine.Value  # Ajoute le nombre d'événements au total
                }
            }
        }
        return $total
    }

    # ------------------------------------------------------------
    # Compte combien d'événements sont rattachés à chaque manager et son équipe.
    # ------------------------------------------------------------
    [Hashtable]StatsUserToManager([hashtable]$stats) {
        $NewStatsTable = @{}  # Nouvelle table pour les stats manager

        Foreach($StatLine in $stats.GetEnumerator()) {
            $user = $this.retreiveUserFromUID($StatLine.Name)  # Récupère l'utilisateur

            # Vérifie si on connaît l'utilisateur
            if($user -ne $null) {
                if($this.CachedManager.ContainsKey($user.hr_I_UID) -eq $true) {  # Si on sait déjà si c'est un manager
                    # Si c'est un manager, rien à faire
                    if($this.CachedManager[$user.hr_I_UID] -eq $true) {
                        # rien à faire
                    } 
                    # Sinon, remonter au manager
                    else {
                        $user = $this.retreiveUserFromUID($user.managerUid)
                    }
                } else {
                    # vérifie si l'utilisateur a des employés
                    $nbEmployee = $this.SQLConnexion.SelectFirst("SELECT COUNT(*) as NbUser FROM BNPPStatistics..refog WHERE managerUid = '$($user.hr_I_UID)'")['NbUser']
                    if ($nbEmployee -eq 0){
                        $this.CachedManager.Add($user.hr_I_UID, $false)  # C'est pas un manager
                        $user = $this.retreiveUserFromUID($user.managerUid)  # remonte au manager
                        if($user -ne $null -and $this.CachedManager.ContainsKey($user.hr_I_UID)-eq $false) {
                            $this.CachedManager.Add($user.hr_I_UID, $true)  # marque le manager comme manager
                        }
                    } else {
                        $this.CachedManager.Add($user.hr_I_UID, $true)  # C'est un manager
                    }
                }
                $employeeID = $user.hr_I_UID 
            } else {
                $employeeID = 'Undefined'  # Si utilisateur pas trouvé
            }
            
            if($employeeID -ne $null) {
                if($NewStatsTable.ContainsKey($employeeID)) {
                    $NewStatsTable[$employeeID] += $StatLine.Value 
                } else {
                    $NewStatsTable.Add($employeeID,$StatLine.Value)  
                }
            }
            
        }
        return $NewStatsTable 
    }

    # ------------------------------------------------------------
    # Compte combien d'utilisateurs sont rattachés à chaque manager.
    # ------------------------------------------------------------
    [Hashtable]PermissionsUserToManager([hashtable]$stats) {
        $NewStatsTable = @{}

        Foreach($StatLine in $stats.GetEnumerator()) {

            $user = $this.retreiveUserFromUID($StatLine.Name)

            # Vérifie si on connaît l'utilisateur
            if($user -ne $null) {
                if($this.CachedManager.ContainsKey($user.hr_I_UID) -eq $true) {
                    # Si c'est un manager, rien à faire
                    if($this.CachedManager[$user.hr_I_UID] -eq $true) {
                        # rien à faire
                    } 
                    # Sinon, remonter au manager
                    else {
                        $user = $this.retreiveUserFromUID($user.managerUid)
                    }
                } else {
                    $nbEmployee = $this.SQLConnexion.SelectFirst("SELECT COUNT(*) as NbUser FROM BNPPStatistics..refog WHERE managerUid = '$($user.hr_I_UID)'")['NbUser']
                    if ($nbEmployee -eq 0){
                        $this.CachedManager.Add($user.hr_I_UID, $false)
                        $user = $this.retreiveUserFromUID($user.managerUid)
                        if($user -ne $null -and $this.CachedManager.ContainsKey($user.hr_I_UID)-eq $false) {
                            $this.CachedManager.Add($user.hr_I_UID, $true)
                        }
                    } else {
                        $this.CachedManager.Add($user.hr_I_UID, $true)
                    }
                }
                $employeeID = $user.hr_I_UID
            } else {
                $employeeID = 'Undefined'
            }
            
            if($employeeID -ne $null) {
                if($NewStatsTable.ContainsKey($employeeID)) {
                    $NewStatsTable[$employeeID] += 1
                } else {
                    $NewStatsTable.Add($employeeID,1)
                }
            }
            
        }
        return $NewStatsTable
    }

    <#
    .OUTPUTS
        BNPPOwnerReferential object fulfilled

    .EXAMPLE
        [OwnerFinder]::find('vs1-101-fra-nsd.fr.net.intra', '\\vs1-101-fra-nsd.fr.net.intra\SIGCM\ITRMG')

    #>
    # ------------------------------------------------------------
    # Recherche le propriétaire d'un partage réseau en analysant l'utilisateur le plus actif sur une période donnée
    # $ServerName : nom du serveur de fichiers
    # $SharePath  : chemin du partage réseau
    # $LookupDays : nombre de jours à analyser pour l'activité
    # Retourne  BNPPOwnerReferential avec le propriétaire trouvé
    # ------------------------------------------------------------
    [BNPPOwnerReferential] find([string]$ServerName, [string]$SharePath, [int]$LookupDays) {
        $owner = $this.findOwnerFromTopUser($ServerName, $SharePath, $LookupDays)  
        return $owner  
    }

    # ------------------------------------------------------------
    # même fonction mais avec une période par défaut de 60 jours
    # ------------------------------------------------------------
    [BNPPOwnerReferential] find([string]$ServerName, [string]$SharePath) {
        return $this.find($ServerName,$SharePath,60)  # Appelle la fonction précédente avec 60 jours par défaut
    }

    # ------------------------------------------------------------
    # Trouve le propriétaire à partir des permissions sur le dossier
    # ------------------------------------------------------------
    [BNPPOwnerReferential] findOwnerFromPermissions([string]$ServerName, [string]$SharePath) {
        $owner = [BNPPOwnerReferential]::new()  # new objet stock le résultat
        $owner.ServerName = $ServerName         # nom du serveur
        $owner.SharePath = $SharePath.Replace("''","'") 

        # Récupère infos du serveur et du dossier
        $filer = $this.SQLConnexion.GetFilerIDByFilerName($ServerName)
        $directory = $this.SQLConnexion.getDirIDByPath($ServerName, $SharePath)
        $stats = $this.getDirectoryPermissions($ServerName, $SharePath, 1,0)  # Récupère les permissions sur le dossier
        $owner.DirID = $directory
        $owner.FilerID = $filer

        <###########################################################################################################>
                     
          
        if ($stats.Count -gt 0){
            $stats = $this.formatPermissionsTable($stats)      # table de hachage (user => 1)
            $stats = $this.PermissionsUserToManager($stats)
            $nbEvents_precleaning = $this.getTotalNumberOfEvents($stats)  # compte le nombre total de perms

            # Si "Undefined" existe, on la met à zéro
            if($stats.ContainsKey("Undefined") -eq $true) {
                $stats.Undefined = 0
            }

            $nbEvents = $this.getTotalNumberOfEvents($stats)   # compte le total

            # Cherche le manager avec le plus de permissions
            $MostActiveOwner = $($stats.GetEnumerator() | Sort-Object -property:Value -Descending).Key[0]
            $UsagePCCiso = $this.getPCUsageCISO($MostActiveOwner, $stats)
            <###########################################################################################################>

            #[system.diagnostics.stopwatch]$stopwatch = [system.diagnostics.stopwatch]::StartNew()
            # Si on a assez d'infos et proprio diff de "Undefined"
            if($stats.Count -gt 1 -and $MostActiveOwner -ne 'Undefined') {
                $RefogOwner = (([RefogModel]::new()).SelectWhere("hr_I_UID = '$MostActiveOwner'"))[0]  # recup infos du proprio
                $RefogOwnerCISO = (([RefogRSSIModel]::new()).SelectWhere("UO_ID_UO = $($RefogOwner.rssiOu)"))[0]  # recup infos CISO
                $owner.CisoOUID = $RefogOwnerCISO.UO_ID_UO
                $owner.OwnerUID = $RefogOwner.hr_I_UID
                $owner.CisoUID = $RefogOwnerCISO.rssiUid
                $owner.ref_flag = $RefogOwnerCISO.ref_flag
                $owner.comment = "Calculation based on $($nbEvents) permissions - $($nbEvents_precleaning) leavers"
            } else {
                $owner.comment = 'Not enough event'  # Pas assez d'infos pour conclure
            }
            #[logger]::log("Section 5 - Total elapsed time : $([Math]::Round($stopwatch.Elapsed.TotalSeconds,2))s")
            
            <###########################################################################################################>


            # Export des informations finales
            # ajout date creation du résultat
            $owner.created_at = [DateTime]::Now

            # si aucun proprietaire trouvé
            if($owner.OwnerUID -eq '') {
                $owner.comment = "Can't find using permissions"
            } else {
                # sinon on précise la règle et calcule pourcentages d'utilisation
                $owner.matching_rule = "Manager, Permissions, Excluding leavers and open access"
                $owner.usage_pc_ciso = ($UsagePCCiso)/($nbEvents)*100
                $owner.usage_pc_owner = ($stats[$MostActiveOwner])/($nbEvents)*100
            }

        } else {
            # si aucune permission trouvée -> ajout en commentaire
            $owner.comment = "Not enough permissions / only open access"
        }
        return $owner 
    }
    
    # ------------------------------------------------------------
    # Trouve le propriétaire à partir de l'usage du partage
    # ------------------------------------------------------------
    [BNPPOwnerReferential] findOwnerFromShareUsage([string]$ServerName, [string]$SharePath) {
        $owner = [BNPPOwnerReferential]::new()         # new objet stock  résultat
        $owner.ServerName = $ServerName                # nom du serveur
        $owner.SharePath = $SharePath.Replace("''","'")

        # Récupère les infod du serveur et dossier
        $filer = $this.SQLConnexion.GetFilerIDByFilerName($ServerName)
        $directory = $this.SQLConnexion.getDirIDByPath($ServerName, $SharePath)
        $owner.DirID = $directory
        $owner.FilerID = $filer

        # formate le chemin du dossier parent pour la requete SQL
        $split = [System.Collections.ArrayList]$SharePath.Split('\')
        $split.RemoveAt($split.Count-1)
        $parent= $split -join '\'
        $parent = "$($parent)\%"

        # requete pour trouver le propriétaire le plus fréquent sur le parent
        $sql = "
            SELECT TOP(1) COUNT(SharePath) AS NBShare, COUNT(SharePath)*100/(SELECT COUNT(*) as TotalShare FROM BNPPStatistics..BNPP_OwnerReferential WHERE SharePath like '$parent' ) AS PercentNbShare, CisoOUID, CisoUID, CISO.ref_flag, CISO.UO_NOM_EN FROM BNPPStatistics..BNPP_OwnerReferential OWR
            LEFT JOIN BNPPStatistics..refog_ciso CISO on OWR.CisoOUID=CISO.UO_ID_UO
            WHERE FilerID = $($owner.FilerID) AND SharePath like '$parent'   AND CisoUID!=''  AND matching_rule != 'Share Usage'
            GROUP BY CisoOUID, CisoUID,CISO.ref_flag, CISO.UO_NOM_EN
            ORDER BY COUNT(SharePath) DESC

        "

        $res = $this.SQLConnexion.SelectFirst($sql)   # Execute la requête récup le premier résultat

        # si propriétaire
        if($res -ne $null -and $res.CisoUID -ne 0) {
            $owner.matching_rule = 'Share Usage'           #  règle utilisée
            $owner.CisoOUID = $res.CisoOUID                # identifiant entité  CISO
            $owner.CisoUID = $res.CisoUID                  # identifiant CISO
            $owner.usage_pc_ciso = $res.PercentNbShare     # % utilisation CISO sur le parent
            $owner.ref_flag = $res.ref_flag
        } else {
            $owner.comment = 'Cannot assign using share usage'  # aucun proprio trouvé
        }

        return $owner
    }


    # ------------------------------------------------------------
    # Trouve le propriétaire à partir de l'utilisateur le plus actif
    # ------------------------------------------------------------
    [BNPPOwnerReferential] findOwnerFromTopUser([string]$ServerName, [string]$SharePath, [int]$LookupDays) {
        $owner = [BNPPOwnerReferential]::new()         # new objet stock le résultat
        $owner.ServerName = $ServerName                # nom du serveur
        $owner.SharePath = $SharePath.Replace("''","'")

        # Récupère les infos du serveur et du dossier
        $filer = $this.SQLConnexion.GetFilerIDByFilerName($ServerName)
        $directory = $this.SQLConnexion.getDirIDByPath($ServerName, $SharePath)
        $stats = $this.getDirectoryStatistics($ServerName, $SharePath, $LookupDays) # récupère les stats d'accès
        $owner.DirID = $directory
        $owner.FilerID = $filer

        <###########################################################################################################>
               
        # Si on a des stats d'accès
        if ($stats.Count -gt 0){
            $stats = $this.formatStatsTable($stats)         # table de hachage (user => nb d'événements)
            $stats = $this.StatsUserToManager($stats)       

            # Ajoute la clé Undefined si null false
            if($stats.ContainsKey('undefined') -eq $false) {
                $stats.Add('Undefined',0)
            }
            <###########################################################################################################>
            
            $nbEvents = $this.getTotalNumberOfEvents($stats)# compte le total d'événements
            <###########################################################################################################>

            # Cherche le manager le plus actif
            $MostActiveOwner = $($stats.GetEnumerator() | Sort-Object -property:Value -Descending).Key[0]
            $UsagePCCiso = $this.getPCUsageCISO($MostActiveOwner, $stats) # calcule activité CISO pour ce manager

            #[system.diagnostics.stopwatch]$stopwatch = [system.diagnostics.stopwatch]::StartNew()
            # Si on a assez d'infos et proprio diff de "Undefined"
            if($stats.Count -gt 1 -and $MostActiveOwner -ne 'Undefined') {
                $RefogOwner = (([RefogModel]::new()).SelectWhere("hr_I_UID = '$MostActiveOwner'"))[0]  # recup infos du proprio
                $RefogOwnerCISO = (([RefogRSSIModel]::new()).SelectWhere("UO_ID_UO = $($RefogOwner.rssiOu)"))[0]  # recup infos CISO
                $owner.CisoOUID = $RefogOwnerCISO.UO_ID_UO
                $owner.OwnerUID = $RefogOwner.hr_I_UID
                $owner.CisoUID = $RefogOwnerCISO.rssiUid
                $owner.ref_flag = $RefogOwnerCISO.ref_flag
            } else {
                $owner.comment = 'Not enough event'  # pas assez d'infos pour conclure
            }
            #[logger]::log("Section 5 - Total elapsed time : $([Math]::Round($stopwatch.Elapsed.TotalSeconds,2))s")
            
            <###########################################################################################################>


            # Export des informations finales
            $owner.created_at = [DateTime]::Now

            # si aucun propriétaire trouvé
            if($owner.OwnerUID -eq '') {
                $owner.comment = "Not enough event - $LookupDays days"
            } else {
                # sinon on précise la règle et calcule pourcentages d'utilisation
                $owner.matching_rule = "Manager, More active entity, $LookupDays days statistics"
                $owner.usage_pc_ciso = ($UsagePCCiso)/($nbEvents)*100
                $owner.usage_pc_owner = ($stats[$MostActiveOwner])/($nbEvents)*100
            }

        } else {
            # si aucune stat trouvée -> ajout en commentaire
            $owner.comment = "Not enough event - $LookupDays days"
        }
        return $owner
    }

}


# ============================================================================
# Remplace tout caractère < 256 par '%'
# ============================================================================

function cleanExtASCIIChar($str) {
    $cArray = $str.ToCharArray() 
    $cArray| ForEach-Object {
            if([int][char]$_ -gt 256) {
                $cArray[$i] = '%'
            }
            $i++  
        }
    $str = -join $cArray
    return $str
}



    cls

    # chronomètre pour durée totale du script
    [system.diagnostics.stopwatch]$stopwatch = [system.diagnostics.stopwatch]::StartNew()

    # instance SQL à la base Varonis
    $vSQL = [VaronisSQL]::new()

    # =====================
    # BOUCLE PRINCIPALE
    # =====================
    # boucle traitant tous les shares avec tag need_review=1
    # stop quand ya plus de share à traiter SelectFirst retunr $null
    while (1) {
        # Récup le share à traiter 
        # FilerID IN (1,2,3,4,5,12,13) : ne traite que certains serveurs
        # need_review=1 : uniquement ceux à revoir
        # comment != 'updating' and comment != 'error' : ignore ceux déjà en cours ou en erreur
        $res = $vSQL.SelectFirst("SELECT TOP(1) * FROM BNPPStatistics..BNPP_OwnerReferential WHERE FilerID IN (1,2,3,4,5,12,13) AND need_review=1 and comment != 'updating' and comment != 'error'")
        if($res -eq $null) {
            # tous les shares review on sort de la boucle
            break
        }
       
        [logger]::log($res.SharePath)
        $i=0
        # Nettoie le chemin
        $res.SharePath = cleanExtASCIIChar($res.SharePath)
        # Affichage jaune du chemin
        Write-host $res.SharePath -ForegroundColor yellow
        # Recharge l'objet complet depuis la base 
        $res = ([BNPPOwnerReferential]::new()).SelectWhere("SharePath like '$($res.SharePath.Replace("'","''"))'")[0]
        if($res -eq $null) {
            # si share introuvable on sort
            break
        }
        # Nettoyage et mise à jour de la date de modification
        $res.SharePath = cleanExtASCIIChar($res.SharePath)
        $res.updated_at = [DateTime]::Now
        $PreviousState = $res.comment

        # Marque le partage comme updating pour les lancement en parallele
        $res.comment = 'updating'
        $res.save()
    
        $SharePath = $res.SharePath
        $FilerName = $res.ServerName
        try {
        # Instance de OwnerFinder
        [OwnerFinder]$OFinder = [OwnerFinder]::new()
        [logger]::log($SharePath)
        [BNPPOwnerReferential]$owner = $null
        # Selon état du précédent partage :
        # Si pas assez d'événements, on élargit la période
        # Si toujours rien, on tente par permissions
        # Si toujours rien, on tente par usage du parent
        # Sinon, on fait la recherche standard (60 jours)
        switch ($PreviousState)
        {
            'Not enough event' {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromTopUser($FilerName, $SharePath,180) # elargit à 180 jours
            }
            'Not enough event - 60 days' {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromTopUser($FilerName, $SharePath,180)
            }
            'Not enough event - 180 days' {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromTopUser($FilerName, $SharePath,365) # elargit à 1 an
            }
            'Not enough event - 365 days' {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromPermissions($FilerName, $SharePath) # tente par permissions
            }
            'Not enough permissions / only open access' {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromShareUsage($FilerName, $SharePath) # tente par usage du parent
            }
            Default {
                [BNPPOwnerReferential]$owner = $OFinder.findOwnerFromTopUser($FilerName, $SharePath,60) # cas standard 60 jours
            }
        }
        # update l'objet owner avec les infos du share
        $owner.SharePath=$res.SharePath
        $owner.created_at = $res.created_at
        # Si on na pas pu attribuer par usage, plus de review
        # Si pas d'événement ou no trouvé, besoin de review
        if($owner.comment -eq "Cannot assign using share usage") {
            $owner.need_review = 0
        }elseif($owner.comment -like 'Not enough event*' -or $owner -like "Can't find using permissions") {
            $owner.need_review = 1
        }
        # Sauvegarde le résultat
        $owner.save()
    
        } catch {
            # erreur, on log et on marque le partage en erreur
            $_
            $res.comment = 'Error'
            $res.save()
            
        }
        
    }
 
    # Affiche les infos de fin
    [logger]::log("Script end. Time elapsed : $([math]::Round($stopwatch.Elapsed.TotalSeconds,2))s", @{color='cyan'})
    $stopwatch.Stop()
