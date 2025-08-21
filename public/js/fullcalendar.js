document.addEventListener('DOMContentLoaded', function () {
  const profissionalSelect = document.getElementById('profissional');
  const calendarEl = document.getElementById('calendar');

  function populateProfessionals() {
    fetch('/api/profissionais')
      .then(response => response.json())
      .then(profissionais => {
        profissionalSelect.innerHTML = '<option value="">Selecione um profissional</option>';
        profissionais.forEach((prof) => {
          const option = document.createElement('option');
          option.value = prof.id;
          option.textContent = `${prof.nome}${prof.especialidade ? ' - ' + prof.especialidade : ''}`;
          profissionalSelect.appendChild(option);
        });
      })
      .catch(() => {
        profissionalSelect.innerHTML = '<option value="">Erro ao carregar profissionais</option>';
      });
  }

  const calendar = new FullCalendar.Calendar(calendarEl, {
    initialView: 'timeGridWeek',
    headerToolbar: {
      left: 'prev,next today',
      center: 'title',
      right: 'dayGridMonth,timeGridWeek,timeGridDay'
    },
    height: 'auto',
    locale: 'pt-br',
    nowIndicator: true,
    slotMinTime: '08:00:00',
    slotMaxTime: '20:00:00',
    events: function (fetchInfo, successCallback, failureCallback) {
      const profissionalId = profissionalSelect.value;
      if (!profissionalId) {
        successCallback([]);
        return;
      }
      const params = new URLSearchParams({
        profissionalId,
        start: fetchInfo.startStr,
        end: fetchInfo.endStr
      });
      fetch(`/api/agendamentos?${params.toString()}`)
        .then(r => r.json())
        .then(data => successCallback(Array.isArray(data) ? data : []))
        .catch(failureCallback);
    }
  });

  profissionalSelect.addEventListener('change', () => {
    calendar.refetchEvents();
  });

  populateProfessionals();
  calendar.render();
});