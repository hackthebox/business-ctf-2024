def banner():
    print('You will be given a file with N = 200 different potential candidates. Every candidates has 6 different skills, with a score 1 <= s <= 10 for each.')
    print('The formulas to calculate their general value are:')
    print('\t<skill>_score = round(6 * (int(s) * <skill>_weight)) + 10')
    print('\toverall_value = round(5 * ((health * 0.18) + (agility * 0.20) + (charisma * 0.21) + (knowledge * 0.08) + (energy * 0.17) + (resourcefulness * 0.16)))')
    print('\tNote: The round() function here is Python 3\'s round(), which uses a concept called Banker\'s Rounding')
    print('The weights for the 6 skills are: health_weight = 0.2, agility_weight = 0.3, charisma_weight = 0.1, knowledge_weight = 0.05, energy_weight = 0.05, resourcefulness_weight = 0.3')
    print('Enter the first 14 candidates ordered in the highest overall values.')
    print('Enter them like so: Name_1 Surname_1 - score_1, Name_2 Surname_2 - score_2, ..., Name_i Surname_i - score_i')
    print('\te.g. Timothy Pempleton - 94, Jimmy Jones - 92, Randolf Ray - 92, ...')

def main():
    banner()
    answer = input('> ')
    data = answer.split(', ')
    if len(data) != 14:
        print('Not a good number of team members...')
        return
    
    ctr = 0
    for d in data:
        if d in solution:
            solution.remove(d)
            ctr += 1

    if ctr == 14:
        flag = open('/flag.txt', 'r').read()
        print(f'You have recruited the best possible companions. Before you leave, take this: {flag}')
    else:
        print('You\'re going to need a better team...')

if __name__ == '__main__':
    solution = ['Jayson Enderby - 98', 'Malva Shreeve - 96', 'Randolf Raybould - 96', 'Shay Sheardown - 95', 'Koo Rue - 94',
                'Tabina Nathon - 94', 'Taber Haile - 93', 'Constanta Rolfs - 93', 'Corette Bursnell - 93', 'Gerri Bielfelt - 92',
                'Andy Swane - 91', 'Colene Vanyatin - 91', 'Lowe Farnan - 91', 'Ashlin Neely - 91']
    main()